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

			if _, err := engine.AddRule(rule); err != nil {
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

	// Import rules command
	importCmd := &cobra.Command{
		Use:   "import <json-file>",
		Short: "Import security rules from JSON file",
		Long:  `Import security rules from a JSON file. Rules will be added to the database, existing rules with same names will be updated.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			engine, err := rules.NewRuleEngine(rulesDbPath)
			if err != nil {
				logrus.Fatalf("Failed to initialize rule engine: %v", err)
			}
			defer engine.Close()

			jsonFile := args[0]
			if err := importRulesFromJSON(engine, jsonFile); err != nil {
				logrus.Fatalf("Failed to import rules: %v", err)
			}

			fmt.Printf("Rules imported successfully from %s\n", jsonFile)
		},
	}

	// Export rules command
	exportCmd := &cobra.Command{
		Use:   "export [json-file]",
		Short: "Export security rules to JSON file",
		Long:  `Export all security rules to a JSON file. If no file specified, output to stdout.`,
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			engine, err := rules.NewRuleEngine(rulesDbPath)
			if err != nil {
				logrus.Fatalf("Failed to initialize rule engine: %v", err)
			}
			defer engine.Close()

			var outputFile string
			if len(args) > 0 {
				outputFile = args[0]
			}

			if err := exportRulesToJSON(engine, outputFile); err != nil {
				logrus.Fatalf("Failed to export rules: %v", err)
			}

			if outputFile != "" {
				fmt.Printf("Rules exported successfully to %s\n", outputFile)
			}
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

	rulesCmd.AddCommand(listCmd, showCmd, addCmd, toggleCmd, deleteCmd, importCmd, exportCmd)
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

func importRulesFromJSON(engine *rules.RuleEngine, jsonFile string) error {
	// Read JSON file
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", jsonFile, err)
	}

	// Parse JSON
	var importRules []rules.SecurityRule
	if err := json.Unmarshal(data, &importRules); err != nil {
		return fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Import rules
	imported := 0
	updated := 0
	for _, rule := range importRules {
		// Check if rule with same name exists
		existingRules, err := engine.GetRules("")
		if err != nil {
			return fmt.Errorf("failed to check existing rules: %v", err)
		}

		var existingRule *rules.SecurityRule
		for _, existing := range existingRules {
			if existing.Name == rule.Name {
				existingRule = &existing
				break
			}
		}

		if existingRule != nil {
			// Update existing rule
			rule.ID = existingRule.ID
			if err := engine.UpdateRule(rule); err != nil {
				return fmt.Errorf("failed to update rule '%s': %v", rule.Name, err)
			}
			updated++
		} else {
			// Add new rule
			if _, err := engine.AddRule(rule); err != nil {
				return fmt.Errorf("failed to add rule '%s': %v", rule.Name, err)
			}
			imported++
		}
	}

	fmt.Printf("Import summary: %d new rules added, %d existing rules updated\n", imported, updated)
	return nil
}

func exportRulesToJSON(engine *rules.RuleEngine, outputFile string) error {
	// Get all rules
	rulesList, err := engine.GetRules("")
	if err != nil {
		return fmt.Errorf("failed to get rules: %v", err)
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(rulesList, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal rules to JSON: %v", err)
	}

	// Output to file or stdout
	if outputFile != "" {
		if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write file %s: %v", outputFile, err)
		}
	} else {
		fmt.Println(string(jsonData))
	}

	return nil
}
