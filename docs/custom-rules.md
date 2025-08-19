# Adding Custom Security Rules

This guide shows how to add custom security rules to KubeSnoop's rule engine.

## Rule Structure

Each security rule is a JSON object with the following fields:

```json
{
  "name": "unique-rule-identifier",
  "category": "Security Category",
  "severity": "HIGH|MEDIUM|LOW", 
  "description": "Human-readable description",
  "remediation": "Specific steps to fix the issue",
  "rule_type": "pod|service|rbac|namespace|node",
  "query": "JSONPath expression to extract data",
  "condition": "Condition to evaluate",
  "enabled": true,
  "tags": "comma,separated,tags"
}
```

## Field Descriptions

- **name**: Unique identifier for the rule
- **category**: Logical grouping (e.g., "Container Security", "Network Security")
- **severity**: Risk level - HIGH, MEDIUM, or LOW
- **description**: What the rule checks for
- **remediation**: How to fix the issue
- **rule_type**: Type of Kubernetes resource to evaluate
- **query**: JSONPath expression to extract values from the resource
- **condition**: Logic to determine if the rule fails
- **enabled**: Whether the rule is active
- **tags**: Keywords for categorization and filtering

## JSONPath Queries

KubeSnoop uses JSONPath to extract data from collected Kubernetes resources:

### Pod Examples
```json
"$.containers[*].image"                          // All container images
"$.containers[*].securityContext.privileged"    // Privileged flag
"$.securityContext.runAsUser"                    // Pod run-as user
"$.hostNetwork"                                  // Host network usage
"$.spec.volumes[*].hostPath"                     // Host path mounts
```

### Service Examples
```json
"$.type"                    // Service type
"$.ports[*].nodePort"       // NodePort values
"$.spec.externalIPs"        // External IP addresses
```

### RBAC Examples
```json
"$.rules[*].verbs[*]"       // All allowed verbs
"$.rules[*].resources[*]"   // All allowed resources
"$.subjects[*].kind"        // Subject types in bindings
```

### Namespace Examples
```json
"$.networkPolicies"         // Network policies in namespace
"$.labels['security.level']" // Security level label
```

## Condition Operators

### Equality
```json
"== true"           // Boolean true
"== false"          // Boolean false  
"== 'NodePort'"     // String match
"== 0"              // Number match
"== null"           // Field is missing/null
```

### String Operations
```json
"endsWith ':latest'"      // Image ends with :latest
"contains 'admin'"        // Contains substring
"NOT contains ':'"        // Does not contain colon
```

### Compound Conditions
```json
"== 0 OR null"           // Either zero or null
"null OR empty"          // Missing or empty object/array
```

### Array Operations
```json
"count == 0"             // Array is empty
"count > 5"              // Array has more than 5 items
```

## Example Rules

### 1. Detect Containers with Added Capabilities
```json
{
  "name": "dangerous-capabilities-added",
  "category": "Container Security",
  "severity": "HIGH",
  "description": "Container adds dangerous Linux capabilities",
  "remediation": "Remove dangerous capabilities like SYS_ADMIN, NET_ADMIN. Use 'drop: [ALL]' and only add required capabilities.",
  "rule_type": "pod",
  "query": "$.containers[*].securityContext.capabilities.add[*]",
  "condition": "== 'SYS_ADMIN' OR == 'NET_ADMIN' OR == 'SYS_TIME'",
  "enabled": true,
  "tags": "capabilities,dangerous,container"
}
```

### 2. Check for Unauthenticated Services
```json
{
  "name": "unauthenticated-service",
  "category": "Network Security", 
  "severity": "MEDIUM",
  "description": "Service may not require authentication",
  "remediation": "Ensure services require proper authentication. Consider using service mesh or ingress authentication.",
  "rule_type": "service",
  "query": "$.metadata.annotations['auth.required']",
  "condition": "== null OR == 'false'",
  "enabled": true,
  "tags": "authentication,service,security"
}
```

### 3. Detect Overprivileged Service Accounts
```json
{
  "name": "service-account-cluster-admin",
  "category": "RBAC",
  "severity": "HIGH", 
  "description": "Service account has cluster-admin permissions",
  "remediation": "Use least-privilege principle. Create specific roles instead of cluster-admin.",
  "rule_type": "rbac",
  "query": "$.roleRef.name",
  "condition": "== 'cluster-admin'",
  "enabled": true,
  "tags": "rbac,cluster-admin,privilege"
}
```

### 4. Check Namespace Security Labels
```json
{
  "name": "missing-security-labels",
  "category": "Governance",
  "severity": "LOW",
  "description": "Namespace missing security classification labels", 
  "remediation": "Add security.level label (public, internal, confidential, restricted)",
  "rule_type": "namespace",
  "query": "$.labels['security.level']",
  "condition": "== null",
  "enabled": true,
  "tags": "labels,governance,classification"
}
```

## Adding Rules via CLI

### Interactive Addition
```bash
# Add rule interactively
./bin/kubesnoop rules add

# Then paste JSON when prompted
```

### Rule Management
```bash
# List all rules
./bin/kubesnoop rules list

# Filter by type
./bin/kubesnoop rules list pod

# Show rule details
./bin/kubesnoop rules show 10

# Disable a rule temporarily
./bin/kubesnoop rules toggle 10 false

# Re-enable a rule
./bin/kubesnoop rules toggle 10 true

# Delete a rule
./bin/kubesnoop rules delete 10
```

## Testing Rules

1. **Add the rule** using the CLI
2. **Run a scan** to see if it triggers: `./bin/kubesnoop --format json`
3. **Check findings** in the output's `security_findings` array
4. **Refine the rule** based on results

## Best Practices

### Rule Naming
- Use descriptive, kebab-case names
- Include the resource type or security domain
- Examples: `privileged-container`, `wildcard-rbac`, `nodeport-service`

### Query Design
- Test JSONPath expressions with sample data
- Use specific queries rather than broad wildcards
- Consider performance impact of complex queries

### Condition Logic
- Keep conditions simple and readable
- Document complex logic in the description
- Test edge cases (null values, empty arrays)

### Severity Guidelines
- **HIGH**: Immediate security risk, potential for privilege escalation
- **MEDIUM**: Important security concern, should be addressed soon
- **LOW**: Best practice violation, improves security posture

### Remediation
- Provide specific, actionable steps
- Include relevant documentation links
- Mention security implications

## Rule Categories

Organize rules into logical categories:

- **Container Security**: Privilege escalation, capabilities, users
- **Host Security**: Host namespaces, host paths, privileged access
- **Network Security**: Network policies, service exposure, ingress
- **RBAC**: Permissions, service accounts, role bindings  
- **Resource Management**: Limits, quotas, resource allocation
- **Image Security**: Tags, registries, scanning policies
- **Governance**: Labels, annotations, compliance requirements
