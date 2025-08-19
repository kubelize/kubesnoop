# Security Policy

## Supported Versions

KubeSnoop follows semantic versioning. Security updates are provided for:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | ✓                  |
| 0.x.x   | ⅹ                  |

## Reporting a Vulnerability

If you discover a security vulnerability in KubeSnoop, please report it responsibly:

1. **DO NOT** create a public issue
2. Email security findings to: kubelize@kubelize.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

## Security Considerations

### Permissions

KubeSnoop requires cluster-wide read permissions to analyze security configurations. The included RBAC configuration follows the principle of least privilege:

- Read-only access to cluster resources
- No write or delete permissions
- No access to secrets by default (configurable)

### Data Collection

By default, KubeSnoop:
- ✅ Redacts sensitive information from output
- ✅ Excludes secrets collection
- ✅ Excludes system namespaces
- ❌ Does not persist data to external systems

### Network Security

When deploying KubeSnoop:
- Runs with non-root user (UID 65534)
- Uses read-only root filesystem
- Drops all Linux capabilities
- No privilege escalation allowed

### Configuration Security

- Configuration is stored in ConfigMaps (non-sensitive)
- Environment variables can override config
- No hardcoded credentials or secrets

## Best Practices

1. **Network Segmentation**: Deploy in a dedicated namespace with appropriate network policies
2. **Resource Limits**: Set appropriate CPU and memory limits
3. **Output Security**: Review output before sharing externally
4. **Access Control**: Limit access to KubeSnoop output and logs
5. **Regular Updates**: Keep KubeSnoop updated to latest security patches
