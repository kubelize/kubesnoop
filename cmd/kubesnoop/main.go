package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kubelize/kubesnoop/internal/collector"
	"github.com/kubelize/kubesnoop/internal/config"
	"github.com/kubelize/kubesnoop/internal/rules"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	kubeconfig   string
	outputFile   string
	outputFormat string
	namespace    string
	interval     time.Duration
	daemon       bool
	dbPath       string
)

func getDefaultDBPath() string {
	if envPath := os.Getenv("KUBESNOOP_DB_PATH"); envPath != "" {
		return envPath
	}
	return "kubesnoop.db"
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "kubesnoop",
		Short: "Kubernetes security information collector",
		Long:  `KubeSnoop collects comprehensive security information from Kubernetes clusters for analysis`,
		Run:   run,
	}

	rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (optional if running in-cluster)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: stdout)")
	rootCmd.Flags().StringVarP(&outputFormat, "format", "f", "json", "Output format (json, yaml)")
	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Specific namespace to scan (default: all)")
	rootCmd.Flags().DurationVarP(&interval, "interval", "i", 0, "Collection interval for daemon mode (e.g., 1h, 30m)")
	rootCmd.Flags().BoolVarP(&daemon, "daemon", "d", false, "Run in daemon mode")
	rootCmd.Flags().StringVar(&dbPath, "db", getDefaultDBPath(), "Path to rules database file")

	// Add rules subcommand
	rootCmd.AddCommand(createRulesCommand())

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

func run(cmd *cobra.Command, args []string) {
	// Setup logging
	logrus.SetLevel(logrus.InfoLevel)
	if os.Getenv("DEBUG") == "true" {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// Create Kubernetes client
	clientset, err := createKubernetesClient()
	if err != nil {
		logrus.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Initialize rule engine
	ruleEngine, err := rules.NewRuleEngine(dbPath)
	if err != nil {
		logrus.Fatalf("Failed to initialize rule engine: %v", err)
	}
	defer ruleEngine.Close()

	// Load configuration
	cfg := config.LoadConfig()

	// Create collector
	col := collector.New(clientset, cfg)

	// Create rule evaluator
	evaluator := rules.NewEvaluator(ruleEngine)

	// Run collection
	if daemon && interval > 0 {
		runDaemon(col, evaluator)
	} else {
		runOnce(col, evaluator)
	}
}

func createKubernetesClient() (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	if kubeconfig != "" {
		// Use provided kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		// Try in-cluster config first
		config, err = rest.InClusterConfig()
		if err != nil {
			// Fall back to default kubeconfig location
			homeDir, _ := os.UserHomeDir()
			kubeconfig := fmt.Sprintf("%s/.kube/config", homeDir)
			config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		}
	}

	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}

func runOnce(col *collector.Collector, evaluator *rules.Evaluator) {
	logrus.Info("Starting single collection run")

	ctx := context.Background()
	result, err := col.CollectAll(ctx, namespace)
	if err != nil {
		logrus.Fatalf("Collection failed: %v", err)
	}

	// Evaluate security rules
	if evaluator != nil {
		logrus.Info("Evaluating security rules")
		findings, err := evaluator.EvaluateClusterInfo(result)
		if err != nil {
			logrus.Errorf("Rule evaluation failed: %v", err)
		} else {
			result.SecurityFindings = findings
			result.Summary.SecurityFindings = len(findings)
			logrus.Infof("Found %d security findings", len(findings))
		}
	}

	if err := outputResult(result); err != nil {
		logrus.Fatalf("Failed to output result: %v", err)
	}

	logrus.Info("Collection completed successfully")
}

func runDaemon(col *collector.Collector, evaluator *rules.Evaluator) {
	logrus.Infof("Starting daemon mode with interval: %v", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once immediately
	runOnce(col, evaluator)

	// Then run on interval
	for range ticker.C {
		logrus.Info("Running scheduled collection")
		runOnce(col, evaluator)
	}
}

func outputResult(result *collector.ClusterInfo) error {
	var data []byte
	var err error

	switch outputFormat {
	case "yaml":
		data, err = result.ToYAML()
	default:
		data, err = json.MarshalIndent(result, "", "  ")
	}

	if err != nil {
		return err
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, data, 0644)
	}

	fmt.Print(string(data))
	return nil
}
