package rules

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// RuleEngine handles security rule evaluation
type RuleEngine struct {
	db *sql.DB
}

// SecurityRule represents a security check rule
type SecurityRule struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
	RuleType    string `json:"rule_type"`    // pod, service, rbac, node, etc.
	Query       string `json:"query"`       // JSONPath or SQL-like query
	Condition   string `json:"condition"`   // evaluation condition
	Enabled     bool   `json:"enabled"`
	Tags        string `json:"tags"`        // comma-separated tags
}

// RuleResult represents the result of a rule evaluation
type RuleResult struct {
	Rule     SecurityRule `json:"rule"`
	Resource string       `json:"resource"`
	Passed   bool         `json:"passed"`
	Message  string       `json:"message"`
	Value    interface{}  `json:"value,omitempty"`
}

func NewRuleEngine(dbPath string) (*RuleEngine, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	engine := &RuleEngine{db: db}
	if err := engine.initDatabase(); err != nil {
		return nil, err
	}

	return engine, nil
}

func (re *RuleEngine) initDatabase() error {
	schema := `
	CREATE TABLE IF NOT EXISTS security_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		category TEXT NOT NULL,
		severity TEXT NOT NULL,
		description TEXT NOT NULL,
		remediation TEXT NOT NULL,
		rule_type TEXT NOT NULL,
		query TEXT NOT NULL,
		condition TEXT NOT NULL,
		enabled BOOLEAN DEFAULT true,
		tags TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_rule_type ON security_rules(rule_type);
	CREATE INDEX IF NOT EXISTS idx_category ON security_rules(category);
	CREATE INDEX IF NOT EXISTS idx_severity ON security_rules(severity);
	CREATE INDEX IF NOT EXISTS idx_enabled ON security_rules(enabled);
	`

	_, err := re.db.Exec(schema)
	if err != nil {
		return err
	}

	// Insert default rules if table is empty
	var count int
	err = re.db.QueryRow("SELECT COUNT(*) FROM security_rules").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		return re.loadDefaultRules()
	}

	return nil
}

func (re *RuleEngine) loadDefaultRules() error {
	defaultRules := []SecurityRule{
		{
			Name:        "privileged-container",
			Category:    "Container Security",
			Severity:    "HIGH",
			Description: "Container is running in privileged mode",
			Remediation: "Remove privileged: true from container security context",
			RuleType:    "pod",
			Query:       "$.containers[*].securityContext.privileged",
			Condition:   "== true",
			Enabled:     true,
			Tags:        "cis,nist,privileged",
		},
		{
			Name:        "root-user-container",
			Category:    "Container Security", 
			Severity:    "MEDIUM",
			Description: "Container may be running as root user",
			Remediation: "Set runAsNonRoot: true and runAsUser to non-zero value",
			RuleType:    "pod",
			Query:       "$.containers[*].securityContext.runAsUser",
			Condition:   "== 0 OR null",
			Enabled:     true,
			Tags:        "cis,root,user",
		},
		{
			Name:        "no-resource-limits",
			Category:    "Resource Management",
			Severity:    "MEDIUM", 
			Description: "Container has no resource limits defined",
			Remediation: "Set CPU and memory limits to prevent resource exhaustion",
			RuleType:    "pod",
			Query:       "$.containers[*].resources.limits",
			Condition:   "null OR empty",
			Enabled:     true,
			Tags:        "resources,limits",
		},
		{
			Name:        "latest-image-tag",
			Category:    "Image Security",
			Severity:    "LOW",
			Description: "Container uses 'latest' tag or no tag specified",
			Remediation: "Use specific image tags for reproducible deployments",
			RuleType:    "pod",
			Query:       "$.containers[*].image",
			Condition:   "endsWith ':latest' OR NOT contains ':'",
			Enabled:     true,
			Tags:        "image,tags,reproducibility",
		},
		{
			Name:        "host-network-usage",
			Category:    "Host Security",
			Severity:    "HIGH",
			Description: "Pod uses host network namespace",
			Remediation: "Avoid hostNetwork unless absolutely necessary",
			RuleType:    "pod",
			Query:       "$.hostNetwork",
			Condition:   "== true",
			Enabled:     true,
			Tags:        "host,network,isolation",
		},
		{
			Name:        "nodeport-service",
			Category:    "Network Security",
			Severity:    "MEDIUM",
			Description: "Service uses NodePort type which exposes ports on all nodes",
			Remediation: "Consider using ClusterIP or LoadBalancer instead",
			RuleType:    "service",
			Query:       "$.type",
			Condition:   "== 'NodePort'",
			Enabled:     true,
			Tags:        "network,exposure",
		},
		{
			Name:        "wildcard-rbac-permissions",
			Category:    "RBAC",
			Severity:    "HIGH",
			Description: "Role has wildcard permissions (*/*)",
			Remediation: "Use least-privilege principle and specify exact resources and verbs",
			RuleType:    "rbac",
			Query:       "$.rules[*].resources[*]",
			Condition:   "== '*'",
			Enabled:     true,
			Tags:        "rbac,wildcard,permissions",
		},
		{
			Name:        "default-service-account",
			Category:    "RBAC",
			Severity:    "LOW",
			Description: "Pod uses default service account",
			Remediation: "Create and use dedicated service accounts for applications",
			RuleType:    "pod",
			Query:       "$.serviceAccount",
			Condition:   "== 'default' OR == '' OR null",
			Enabled:     true,
			Tags:        "rbac,service-account",
		},
		{
			Name:        "no-network-policies",
			Category:    "Network Security",
			Severity:    "MEDIUM",
			Description: "Namespace has no network policies - all traffic allowed by default",
			Remediation: "Implement network policies to restrict pod-to-pod communication",
			RuleType:    "namespace",
			Query:       "$.networkPolicies",
			Condition:   "count == 0",
			Enabled:     true,
			Tags:        "network,policies,segmentation",
		},
	}

	for _, rule := range defaultRules {
		err := re.AddRule(rule)
		if err != nil {
			return fmt.Errorf("failed to add default rule %s: %v", rule.Name, err)
		}
	}

	return nil
}

func (re *RuleEngine) AddRule(rule SecurityRule) error {
	query := `
	INSERT INTO security_rules 
	(name, category, severity, description, remediation, rule_type, query, condition, enabled, tags)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := re.db.Exec(query, rule.Name, rule.Category, rule.Severity, 
		rule.Description, rule.Remediation, rule.RuleType, rule.Query, 
		rule.Condition, rule.Enabled, rule.Tags)
	
	return err
}

func (re *RuleEngine) GetRules(ruleType string) ([]SecurityRule, error) {
	query := "SELECT id, name, category, severity, description, remediation, rule_type, query, condition, enabled, tags FROM security_rules WHERE enabled = true"
	args := []interface{}{}
	
	if ruleType != "" {
		query += " AND rule_type = ?"
		args = append(args, ruleType)
	}

	rows, err := re.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []SecurityRule
	for rows.Next() {
		var rule SecurityRule
		err := rows.Scan(&rule.ID, &rule.Name, &rule.Category, &rule.Severity,
			&rule.Description, &rule.Remediation, &rule.RuleType, &rule.Query,
			&rule.Condition, &rule.Enabled, &rule.Tags)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func (re *RuleEngine) UpdateRule(id int, rule SecurityRule) error {
	query := `
	UPDATE security_rules 
	SET name=?, category=?, severity=?, description=?, remediation=?, 
	    rule_type=?, query=?, condition=?, enabled=?, tags=?, updated_at=CURRENT_TIMESTAMP
	WHERE id=?
	`
	_, err := re.db.Exec(query, rule.Name, rule.Category, rule.Severity,
		rule.Description, rule.Remediation, rule.RuleType, rule.Query,
		rule.Condition, rule.Enabled, rule.Tags, id)
	
	return err
}

func (re *RuleEngine) DeleteRule(id int) error {
	_, err := re.db.Exec("DELETE FROM security_rules WHERE id = ?", id)
	return err
}

func (re *RuleEngine) EnableRule(id int, enabled bool) error {
	_, err := re.db.Exec("UPDATE security_rules SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", enabled, id)
	return err
}

func (re *RuleEngine) Close() error {
	return re.db.Close()
}
