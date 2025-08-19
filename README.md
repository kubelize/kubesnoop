# KubeSnoop

A Kubernetes cluster security information collection and evalutaion tool.

## Overview

KubeSnoop systematically collects comprehensive security-relevant information from Kubernetes clusters. It focuses on identifying misconfigurations, security vulnerabilities, and compliance gaps across your cluster infrastructure.

## Features

### 🔍 Comprehensive Data Collection
- **Pod Security**: Security contexts, privilege escalation, capabilities
- **RBAC Analysis**: Roles, bindings, service accounts, permissions
- **Network Security**: Policies, service exposures, ingress configurations
- **Resource Management**: Limits, quotas, resource allocation
- **Node Security**: Configurations, taints, conditions
- **Image Security**: Tag analysis, registry information

### 📊 Database-Driven Rule Engine
- **Flexible Rules**: Store security rules in SQLite database
- **Dynamic Evaluation**: Add/modify rules without code changes
- **Rule Management**: CLI commands for rule CRUD operations
- **Custom Conditions**: JSONPath queries with flexible conditions
- **Rule Categories**: Organize rules by type and severity

### 🤖 AI-Ready Output
- Structured JSON/YAML output optimized for AI analysis
- Standardized security finding categories
- Risk severity classification
- Remediation guidance templates

### 🛡️ Security-First Design
- Read-only cluster access
- Non-root execution
- Configurable data redaction
- Minimal resource footprint

## Quick Start

### Local Development
```bash
# Clone and build
git clone https://github.com/kubelize/kubesnoop.git
cd kubesnoop
make build

# Run against local cluster
./scripts/run-local.sh
```

### Cluster Deployment
```bash
# Deploy to cluster
make deploy

# Check status
kubectl get pods -n kubesnoop

# View output
kubectl logs -n kubesnoop -l app=kubesnoop
```

## Usage

### Command Line Options
```bash
# Single scan
./bin/kubesnoop --format json --output cluster-report.json

# Daemon mode (periodic collection)
./bin/kubesnoop --daemon --interval 1h

# Target specific namespace
./bin/kubesnoop --namespace production

# Custom kubeconfig and database
./bin/kubesnoop --kubeconfig /path/to/config --db /path/to/rules.db
```

### Rule Management
```bash
# List all security rules
./bin/kubesnoop rules list

# Show specific rule details
./bin/kubesnoop rules show 1

# List rules by type
./bin/kubesnoop rules list pod

# Enable/disable a rule
./bin/kubesnoop rules toggle 1 false

# Delete a rule
./bin/kubesnoop rules delete 5
```

### Configuration
Create `kubesnoop.yaml`:
```yaml
security_focus: true
detailed_analysis: true
exclude_namespaces:
  - kube-system
  - kube-public
modules:
  pods: true
  rbac: true
  network_policies: true
  secrets: false
```

## AI Integration

KubeSnoop output is designed to work seamlessly with AI analysis:### Sample Analysis Workflow
1. **Collect Data**: `kubesnoop --format json --output cluster.json`
2. **AI Analysis**: Use provided prompt templates with GPT-4/Claude
3. **Review Results**: Validate AI recommendations
4. **Implement Fixes**: Apply suggested security improvements

### Example AI Prompt
```
Analyze this Kubernetes cluster for security vulnerabilities:
[kubesnoop output]

Provide prioritized recommendations focusing on:
- Critical security risks
- Compliance violations  
- Best practice deviations
```

## Security Findings

KubeSnoop automatically identifies common security issues:

### High Severity
- Privileged containers
- Host namespace usage
- Wildcard RBAC permissions
- Missing network policies

### Medium Severity  
- Root user containers
- Missing resource limits
- NodePort services
- Default service accounts

### Low Severity
- Latest image tags
- Missing labels
- Outdated configurations

## Architecture

TBD

## Deployment Options

### 1. One-time Analysis
```bash
kubectl run kubesnoop --image=kubesnoop:latest --rm -it --restart=Never
```

### 2. Scheduled Jobs
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kubesnoop-scan
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: kubesnoop
            image: kubesnoop:latest
```

### 3. Continuous Monitoring
```bash
# Deploy as Deployment with daemon mode
kubectl apply -f deploy/
```

## Configuration Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `security_focus` | `true` | Enable security-focused analysis |
| `detailed_analysis` | `false` | Include detailed resource information |
| `exclude_namespaces` | `["kube-system"]` | Namespaces to skip |
| `redact_sensitive` | `true` | Redact sensitive information |
| `modules.*` | `true` | Enable/disable collection modules |

## RBAC Requirements

KubeSnoop requires read access to:
- Pods, Services, Nodes
- NetworkPolicies, Ingresses
- Roles, RoleBindings, ClusterRoles, ClusterRoleBindings
- ServiceAccounts, Secrets (optional)
- ConfigMaps, PersistentVolumes

See `deploy/rbac.yaml` for complete permissions.

## Security Considerations

### Permissions
- **Read-only**: No write/delete cluster permissions
- **Least Privilege**: Minimal required access
- **Optional Secrets**: Secrets collection disabled by default

### Deployment Security
- Non-root user (UID 65534)
- Read-only root filesystem
- No privilege escalation
- Dropped capabilities
- Resource limits enforced

### Data Handling
- Sensitive data redaction by default
- No persistent storage
- Configurable output destinations
- Encryption in transit

## Development

### Building
```bash
# Build binary
make build

# Build Docker image
make docker-build

# Run tests
make test

# Lint code
make lint
```

### Contributing
1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure security best practices
5. Submit pull request

## Examples

See the `examples/` directory for:
- Sample output files
- Configuration examples
- Integration scripts

## Roadmap

- [ ] Pod Security Standards analysis
- [ ] Admission controller detection
- [ ] Helm Chart
- [ ] Prometheus metrics export
- [ ] Grafana Dashboards
- [ ] Web dashboard interface

## Support

- 📚 [Documentation](https://github.com/kubelize/kubesnoop/wiki) WIP!!!
- 🐛 [Issues](https://github.com/kubelize/kubesnoop/issues)
- 💬 [Discussions](https://github.com/kubelize/kubesnoop/discussions)
- 🔒 [Security Policy](SECURITY.md)

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
