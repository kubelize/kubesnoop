package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/kubelize/kubesnoop/internal/rules"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func createRulesCommand() *cobra.Command {
	var rulesDbPath string

	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage security rules",
		Long:  `Manage security rules used for cluster analysis`,
	}

	rulesCmd.PersistentFlags().StringVar(&rulesDbPath, "db", "kubesnoop.db", "Path to rules database file")

	// List rules command
	listCmd := &cobra.Command{
		Use:   "list [rule-type]",
		Short: "List security rules",
		Long:  `List all security rules or filter by rule type (pod, service, rbac, namespace)`,
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			engine, err := rules.NewRuleEngine(rulesDbPath)
			if err != nil {
				logrus.Fatalf("Failed to initialize rule engine: %v", err)
			}
			defer engine.Close()

			var ruleType string
			if len(args) > 0 {
				ruleType = args[0]
			}

			rulesList, err := engine.GetRules(ruleType)
			if err != nil {
				logrus.Fatalf("Failed to get rules: %v", err)
			}

			printRulesTable(rulesList)
		},
	}

	// Show rule command
	showCmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show detailed information about a rule",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			engine, err := rules.NewRuleEngine(rulesDbPath)
			if err != nil {
				logrus.Fatalf("Failed to initialize rule engine: %v", err)
			}
			defer engine.Close()

			id, err := strconv.Atoi(args[0])
			if err != nil {
				logrus.Fatalf("Invalid rule ID: %v", err)
			}

			rulesList, err := engine.GetRules("")
			if err != nil {
				logrus.Fatalf("Failed to get rules: %v", err)
			}

			var rule *rules.SecurityRule
			for _, r := range rulesList {
				if r.ID == id {
					rule = &r
					break
				}
			}

			if rule == nil {
				logrus.Fatalf("Rule with ID %d not found", id)
			}

			printRuleDetails(*rule)
		},
	}

	// Add rule command
	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new security rule",
		Long:  `Add a new security rule from JSON input`,
		Run: func(cmd *cobra.Command, args []string) {
			engine, err := rules.NewRuleEngine(rulesDbPath)
			if err != nil {
				logrus.Fatalf("Failed to initialize rule engine: %v", err)
			}
			defer engine.Close()

			fmt.Print("Enter rule definition (JSON): ")
			var rule rules.SecurityRule
			decoder := json.NewDecoder(os.Stdin)
			if err := decoder.Decode(&rule); err != nil {
				logrus.Fatalf("Failed to parse rule JSON: %v", err)
			}

			if err := engine.AddRule(rule); err != nil {
				logrus.Fatalf("Failed to add rule: %v", err)
			}

			fmt.Printf("Rule '%s' added successfully\n", rule.Name)
		},
	}

	// Enable/disable rule command
	toggleCmd := &cobra.Command{
		Use:   "toggle <id> <enabled>",
		Short: "Enable or disable a rule",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			engine, err := rules.NewRuleEngine(rulesDbPath)
			if err != nil {
				logrus.Fatalf("Failed to initialize rule engine: %v", err)
			}
			defer engine.Close()

			id, err := strconv.Atoi(args[0])
			if err != nil {
				logrus.Fatalf("Invalid rule ID: %v", err)
			}

			enabled, err := strconv.ParseBool(args[1])
			if err != nil {
				logrus.Fatalf("Invalid enabled value (use true/false): %v", err)
			}

			if err := engine.EnableRule(id, enabled); err != nil {
				logrus.Fatalf("Failed to update rule: %v", err)
			}

			status := "disabled"
			if enabled {
				status = "enabled"
			}
			fmt.Printf("Rule %d %s successfully\n", id, status)
		},
	}

	// Delete rule command
	deleteCmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a security rule",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			engine, err := rules.NewRuleEngine(rulesDbPath)
			if err != nil {
				logrus.Fatalf("Failed to initialize rule engine: %v", err)
			}
			defer engine.Close()

			id, err := strconv.Atoi(args[0])
			if err != nil {
				logrus.Fatalf("Invalid rule ID: %v", err)
			}

			if err := engine.DeleteRule(id); err != nil {
				logrus.Fatalf("Failed to delete rule: %v", err)
			}

			fmt.Printf("Rule %d deleted successfully\n", id)
		},
	}

	rulesCmd.AddCommand(listCmd, showCmd, addCmd, toggleCmd, deleteCmd)
	return rulesCmd
}

func printRulesTable(rulesList []rules.SecurityRule) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tTYPE\tCATEGORY\tSEVERITY\tENABLED")
	fmt.Fprintln(w, "--\t----\t----\t--------\t--------\t-------")
	
	for _, rule := range rulesList {
		enabled := "No"
		if rule.Enabled {
			enabled = "Yes"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", 
			rule.ID, rule.Name, rule.RuleType, rule.Category, rule.Severity, enabled)
	}
	
	w.Flush()
}

func printRuleDetails(rule rules.SecurityRule) {
	fmt.Printf("ID: %d\n", rule.ID)
	fmt.Printf("Name: %s\n", rule.Name)
	fmt.Printf("Type: %s\n", rule.RuleType)
	fmt.Printf("Category: %s\n", rule.Category)
	fmt.Printf("Severity: %s\n", rule.Severity)
	fmt.Printf("Enabled: %t\n", rule.Enabled)
	fmt.Printf("Description: %s\n", rule.Description)
	fmt.Printf("Remediation: %s\n", rule.Remediation)
	fmt.Printf("Query: %s\n", rule.Query)
	fmt.Printf("Condition: %s\n", rule.Condition)
	fmt.Printf("Tags: %s\n", rule.Tags)
}
