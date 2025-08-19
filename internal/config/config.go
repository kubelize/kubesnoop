package config

import (
	"os"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	// Collection settings
	IncludeSecrets      bool     `mapstructure:"include_secrets"`
	ExcludeNamespaces   []string `mapstructure:"exclude_namespaces"`
	SecurityFocus       bool     `mapstructure:"security_focus"`
	DetailedAnalysis    bool     `mapstructure:"detailed_analysis"`
	
	// Output settings
	RedactSensitive     bool     `mapstructure:"redact_sensitive"`
	CompressionEnabled  bool     `mapstructure:"compression_enabled"`
	
	// Collection modules
	Modules struct {
		Pods            bool `mapstructure:"pods"`
		Services        bool `mapstructure:"services"`
		NetworkPolicies bool `mapstructure:"network_policies"`
		RBAC            bool `mapstructure:"rbac"`
		Secrets         bool `mapstructure:"secrets"`
		ConfigMaps      bool `mapstructure:"configmaps"`
		Nodes           bool `mapstructure:"nodes"`
		Namespaces      bool `mapstructure:"namespaces"`
		Events          bool `mapstructure:"events"`
		PodSecurityStandards bool `mapstructure:"pod_security_standards"`
	} `mapstructure:"modules"`
}

func LoadConfig() *Config {
	viper.SetConfigName("kubesnoop")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/kubesnoop/")
	viper.AddConfigPath("$HOME/.kubesnoop")
	viper.AddConfigPath(".")

	// Environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("KUBESNOOP")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Default values
	setDefaults()

	// Try to read config file
	if err := viper.ReadInConfig(); err != nil {
		// Config file not found, use defaults
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			panic(err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		panic(err)
	}

	return &config
}

func setDefaults() {
	// Collection settings
	viper.SetDefault("include_secrets", false)
	viper.SetDefault("exclude_namespaces", []string{"kube-system", "kube-public", "kube-node-lease"})
	viper.SetDefault("security_focus", true)
	viper.SetDefault("detailed_analysis", false)
	
	// Output settings  
	viper.SetDefault("redact_sensitive", true)
	viper.SetDefault("compression_enabled", false)
	
	// Collection modules - enable all by default
	viper.SetDefault("modules.pods", true)
	viper.SetDefault("modules.services", true)
	viper.SetDefault("modules.network_policies", true)
	viper.SetDefault("modules.rbac", true)
	viper.SetDefault("modules.secrets", false) // Disabled by default for security
	viper.SetDefault("modules.configmaps", true)
	viper.SetDefault("modules.nodes", true)
	viper.SetDefault("modules.namespaces", true)
	viper.SetDefault("modules.events", true)
	viper.SetDefault("modules.pod_security_standards", true)
	
	// Override with environment if in cluster
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		viper.SetDefault("security_focus", true)
		viper.SetDefault("detailed_analysis", true)
	}
}
