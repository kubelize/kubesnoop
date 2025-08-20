package rules

import (
	"database/sql"

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
	RuleType    string `json:"rule_type"` // pod, service, rbac, node, etc.
	Query       string `json:"query"`     // JSONPath or SQL-like query
	Condition   string `json:"condition"` // evaluation condition
	Enabled     bool   `json:"enabled"`
	Tags        string `json:"tags"` // comma-separated tags
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
	db, err := sql.Open("sqlite", dbPath)
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
	return err
}

func (re *RuleEngine) AddRule(rule SecurityRule) (int64, error) {
	query := `
	INSERT INTO security_rules 
	(name, category, severity, description, remediation, rule_type, query, condition, enabled, tags)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	result, err := re.db.Exec(query, rule.Name, rule.Category, rule.Severity,
		rule.Description, rule.Remediation, rule.RuleType, rule.Query,
		rule.Condition, rule.Enabled, rule.Tags)

	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
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

func (re *RuleEngine) UpdateRuleByID(id int, rule SecurityRule) error {
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

func (re *RuleEngine) UpdateRule(rule SecurityRule) error {
	return re.UpdateRuleByID(rule.ID, rule)
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
