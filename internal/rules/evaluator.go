package rules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kubelize/kubesnoop/internal/collector"
	"github.com/tidwall/gjson"
)

// Evaluator handles rule evaluation against collected data
type Evaluator struct {
	engine *RuleEngine
}

func NewEvaluator(engine *RuleEngine) *Evaluator {
	return &Evaluator{engine: engine}
}

// EvaluateClusterInfo evaluates all rules against the collected cluster information
func (e *Evaluator) EvaluateClusterInfo(info *collector.ClusterInfo) ([]collector.SecurityFinding, error) {
	var findings []collector.SecurityFinding

	// Evaluate pod rules
	podFindings, err := e.evaluatePods(info.Pods)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate pod rules: %v", err)
	}
	findings = append(findings, podFindings...)

	// Evaluate service rules
	serviceFindings, err := e.evaluateServices(info.Services)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate service rules: %v", err)
	}
	findings = append(findings, serviceFindings...)

	// Evaluate RBAC rules
	rbacFindings, err := e.evaluateRBAC(info.RBAC)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate RBAC rules: %v", err)
	}
	findings = append(findings, rbacFindings...)

	// Evaluate namespace rules
	namespaceFindings, err := e.evaluateNamespaces(info.Namespaces, info.NetworkPolicies)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate namespace rules: %v", err)
	}
	findings = append(findings, namespaceFindings...)

	return findings, nil
}

func (e *Evaluator) evaluatePods(pods []collector.PodInfo) ([]collector.SecurityFinding, error) {
	rules, err := e.engine.GetRules("pod")
	if err != nil {
		return nil, err
	}

	var findings []collector.SecurityFinding

	for _, pod := range pods {
		podData, err := json.Marshal(pod)
		if err != nil {
			continue
		}

		resourceName := fmt.Sprintf("Pod/%s/%s", pod.Namespace, pod.Name)

		for _, rule := range rules {
			result := e.evaluateRule(rule, string(podData), resourceName)
			if !result.Passed {
				findings = append(findings, collector.SecurityFinding{
					Severity:    rule.Severity,
					Category:    rule.Category,
					Resource:    resourceName,
					Message:     result.Message,
					Remediation: rule.Remediation,
				})
			}
		}
	}

	return findings, nil
}

func (e *Evaluator) evaluateServices(services []collector.ServiceInfo) ([]collector.SecurityFinding, error) {
	rules, err := e.engine.GetRules("service")
	if err != nil {
		return nil, err
	}

	var findings []collector.SecurityFinding

	for _, service := range services {
		serviceData, err := json.Marshal(service)
		if err != nil {
			continue
		}

		resourceName := fmt.Sprintf("Service/%s/%s", service.Namespace, service.Name)

		for _, rule := range rules {
			result := e.evaluateRule(rule, string(serviceData), resourceName)
			if !result.Passed {
				findings = append(findings, collector.SecurityFinding{
					Severity:    rule.Severity,
					Category:    rule.Category,
					Resource:    resourceName,
					Message:     result.Message,
					Remediation: rule.Remediation,
				})
			}
		}
	}

	return findings, nil
}

func (e *Evaluator) evaluateRBAC(rbac collector.RBACInfo) ([]collector.SecurityFinding, error) {
	rules, err := e.engine.GetRules("rbac")
	if err != nil {
		return nil, err
	}

	var findings []collector.SecurityFinding

	// Evaluate cluster roles
	for _, role := range rbac.ClusterRoles {
		roleData, err := json.Marshal(role)
		if err != nil {
			continue
		}

		resourceName := fmt.Sprintf("ClusterRole/%s", role.Name)

		for _, rule := range rules {
			result := e.evaluateRule(rule, string(roleData), resourceName)
			if !result.Passed {
				findings = append(findings, collector.SecurityFinding{
					Severity:    rule.Severity,
					Category:    rule.Category,
					Resource:    resourceName,
					Message:     result.Message,
					Remediation: rule.Remediation,
				})
			}
		}
	}

	// Evaluate roles
	for _, role := range rbac.Roles {
		roleData, err := json.Marshal(role)
		if err != nil {
			continue
		}

		resourceName := fmt.Sprintf("Role/%s/%s", role.Namespace, role.Name)

		for _, rule := range rules {
			result := e.evaluateRule(rule, string(roleData), resourceName)
			if !result.Passed {
				findings = append(findings, collector.SecurityFinding{
					Severity:    rule.Severity,
					Category:    rule.Category,
					Resource:    resourceName,
					Message:     result.Message,
					Remediation: rule.Remediation,
				})
			}
		}
	}

	return findings, nil
}

func (e *Evaluator) evaluateNamespaces(namespaces []collector.NamespaceInfo, policies []collector.NetworkPolicyInfo) ([]collector.SecurityFinding, error) {
	rules, err := e.engine.GetRules("namespace")
	if err != nil {
		return nil, err
	}

	var findings []collector.SecurityFinding

	// Create a map of namespaces with their network policies
	namespacePolicies := make(map[string][]collector.NetworkPolicyInfo)
	for _, policy := range policies {
		namespacePolicies[policy.Namespace] = append(namespacePolicies[policy.Namespace], policy)
	}

	for _, ns := range namespaces {
		// Create evaluation data structure
		nsData := struct {
			collector.NamespaceInfo
			NetworkPolicies []collector.NetworkPolicyInfo `json:"networkPolicies"`
		}{
			NamespaceInfo:   ns,
			NetworkPolicies: namespacePolicies[ns.Name],
		}

		namespaceData, err := json.Marshal(nsData)
		if err != nil {
			continue
		}

		resourceName := fmt.Sprintf("Namespace/%s", ns.Name)

		for _, rule := range rules {
			result := e.evaluateRule(rule, string(namespaceData), resourceName)
			if !result.Passed {
				findings = append(findings, collector.SecurityFinding{
					Severity:    rule.Severity,
					Category:    rule.Category,
					Resource:    resourceName,
					Message:     result.Message,
					Remediation: rule.Remediation,
				})
			}
		}
	}

	return findings, nil
}

// evaluateRule evaluates a single rule against JSON data
func (e *Evaluator) evaluateRule(rule SecurityRule, jsonData, resourceName string) RuleResult {
	result := RuleResult{
		Rule:     rule,
		Resource: resourceName,
		Passed:   true,
		Message:  "",
	}

	// Extract value using JSONPath query
	gjsonResult := gjson.Get(jsonData, rule.Query)
	if !gjsonResult.Exists() && !strings.Contains(rule.Condition, "null") {
		result.Passed = true // No value found, rule doesn't apply
		return result
	}

	// Evaluate condition
	passed, message := e.evaluateCondition(gjsonResult, rule.Condition, rule.Description)
	result.Passed = passed
	result.Message = message
	result.Value = gjsonResult.Value()

	return result
}

// evaluateCondition evaluates a condition against a gjson result
func (e *Evaluator) evaluateCondition(value gjson.Result, condition, description string) (bool, string) {
	condition = strings.TrimSpace(condition)

	// Handle different condition types
	if strings.Contains(condition, "==") {
		parts := strings.SplitN(condition, "==", 2)
		if len(parts) != 2 {
			return true, ""
		}
		
		expected := strings.TrimSpace(parts[1])
		actual := value.String()

		// Handle special cases
		if expected == "true" {
			if value.Bool() {
				return false, description
			}
		} else if expected == "false" {
			if !value.Bool() {
				return false, description
			}
		} else if expected == "null" {
			if !value.Exists() {
				return false, description
			}
		} else if expected == "'default'" || expected == "\"default\"" {
			if actual == "default" || actual == "" {
				return false, description
			}
		} else if expected == "0" {
			if value.Int() == 0 {
				return false, description
			}
		} else if strings.Trim(expected, "'\"") == actual {
			return false, description
		}

	} else if strings.Contains(condition, "null OR") {
		// Handle compound conditions like "== 0 OR null"
		if !value.Exists() {
			return false, description
		}
		
		// Check the other condition
		if strings.Contains(condition, "== 0") && value.Int() == 0 {
			return false, description
		}

	} else if strings.Contains(condition, "endsWith") {
		actual := value.String()
		if strings.Contains(condition, ":latest") && strings.HasSuffix(actual, ":latest") {
			return false, description
		}

	} else if strings.Contains(condition, "NOT contains") {
		actual := value.String()
		if strings.Contains(condition, ":") && !strings.Contains(actual, ":") {
			return false, description
		}

	} else if strings.Contains(condition, "count == 0") {
		if value.IsArray() && len(value.Array()) == 0 {
			return false, description
		}

	} else if condition == "null OR empty" {
		if !value.Exists() || (value.IsObject() && len(value.Map()) == 0) {
			return false, description
		}
	}

	return true, ""
}
