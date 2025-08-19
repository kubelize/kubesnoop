package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kubelize/kubesnoop/internal/config"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes"
)

type Collector struct {
	clientset *kubernetes.Clientset
	config    *config.Config
}

type ClusterInfo struct {
	CollectionTime   time.Time         `json:"collection_time" yaml:"collection_time"`
	ClusterVersion   string           `json:"cluster_version" yaml:"cluster_version"`
	Nodes            []NodeInfo       `json:"nodes,omitempty" yaml:"nodes,omitempty"`
	Namespaces       []NamespaceInfo  `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
	Pods             []PodInfo        `json:"pods,omitempty" yaml:"pods,omitempty"`
	Services         []ServiceInfo    `json:"services,omitempty" yaml:"services,omitempty"`
	NetworkPolicies  []NetworkPolicyInfo `json:"network_policies,omitempty" yaml:"network_policies,omitempty"`
	RBAC             RBACInfo         `json:"rbac,omitempty" yaml:"rbac,omitempty"`
	SecurityFindings []SecurityFinding `json:"security_findings,omitempty" yaml:"security_findings,omitempty"`
	Summary          ClusterSummary   `json:"summary" yaml:"summary"`
}

type NodeInfo struct {
	Name        string            `json:"name" yaml:"name"`
	Version     string            `json:"version" yaml:"version"`
	OS          string            `json:"os" yaml:"os"`
	Kernel      string            `json:"kernel" yaml:"kernel"`
	Container   string            `json:"container_runtime" yaml:"container_runtime"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Taints      []corev1.Taint    `json:"taints,omitempty" yaml:"taints,omitempty"`
	Conditions  []corev1.NodeCondition `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

type NamespaceInfo struct {
	Name        string            `json:"name" yaml:"name"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Phase       corev1.NamespacePhase `json:"phase" yaml:"phase"`
}

type PodInfo struct {
	Name              string                      `json:"name" yaml:"name"`
	Namespace         string                      `json:"namespace" yaml:"namespace"`
	Labels            map[string]string           `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations       map[string]string           `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	ServiceAccount    string                      `json:"service_account" yaml:"service_account"`
	SecurityContext   *corev1.PodSecurityContext  `json:"security_context,omitempty" yaml:"security_context,omitempty"`
	Containers        []ContainerInfo             `json:"containers" yaml:"containers"`
	Owner             string                      `json:"owner,omitempty" yaml:"owner,omitempty"`
	Phase             corev1.PodPhase             `json:"phase" yaml:"phase"`
	HostNetwork       bool                        `json:"host_network" yaml:"host_network"`
	HostPID           bool                        `json:"host_pid" yaml:"host_pid"`
	HostIPC           bool                        `json:"host_ipc" yaml:"host_ipc"`
}

type ContainerInfo struct {
	Name            string                        `json:"name" yaml:"name"`
	Image           string                        `json:"image" yaml:"image"`
	SecurityContext *corev1.SecurityContext       `json:"security_context,omitempty" yaml:"security_context,omitempty"`
	Resources       corev1.ResourceRequirements   `json:"resources,omitempty" yaml:"resources,omitempty"`
	Ports           []corev1.ContainerPort        `json:"ports,omitempty" yaml:"ports,omitempty"`
}

type ServiceInfo struct {
	Name        string                 `json:"name" yaml:"name"`
	Namespace   string                 `json:"namespace" yaml:"namespace"`
	Type        corev1.ServiceType     `json:"type" yaml:"type"`
	Ports       []corev1.ServicePort   `json:"ports,omitempty" yaml:"ports,omitempty"`
	Selector    map[string]string      `json:"selector,omitempty" yaml:"selector,omitempty"`
	ExternalIPs []string               `json:"external_ips,omitempty" yaml:"external_ips,omitempty"`
}

type NetworkPolicyInfo struct {
	Name      string                             `json:"name" yaml:"name"`
	Namespace string                             `json:"namespace" yaml:"namespace"`
	Spec      networkingv1.NetworkPolicySpec     `json:"spec" yaml:"spec"`
}

type RBACInfo struct {
	ClusterRoles        []rbacv1.ClusterRole        `json:"cluster_roles,omitempty" yaml:"cluster_roles,omitempty"`
	ClusterRoleBindings []rbacv1.ClusterRoleBinding `json:"cluster_role_bindings,omitempty" yaml:"cluster_role_bindings,omitempty"`
	Roles               []rbacv1.Role               `json:"roles,omitempty" yaml:"roles,omitempty"`
	RoleBindings        []rbacv1.RoleBinding        `json:"role_bindings,omitempty" yaml:"role_bindings,omitempty"`
	ServiceAccounts     []corev1.ServiceAccount     `json:"service_accounts,omitempty" yaml:"service_accounts,omitempty"`
}

type SecurityFinding struct {
	Severity    string `json:"severity" yaml:"severity"`
	Category    string `json:"category" yaml:"category"`
	Resource    string `json:"resource" yaml:"resource"`
	Message     string `json:"message" yaml:"message"`
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

type ClusterSummary struct {
	TotalNodes       int `json:"total_nodes" yaml:"total_nodes"`
	TotalNamespaces  int `json:"total_namespaces" yaml:"total_namespaces"`
	TotalPods        int `json:"total_pods" yaml:"total_pods"`
	TotalServices    int `json:"total_services" yaml:"total_services"`
	SecurityFindings int `json:"security_findings" yaml:"security_findings"`
}

func New(clientset *kubernetes.Clientset, config *config.Config) *Collector {
	return &Collector{
		clientset: clientset,
		config:    config,
	}
}

func (c *Collector) CollectAll(ctx context.Context, targetNamespace string) (*ClusterInfo, error) {
	logrus.Info("Starting cluster information collection")

	info := &ClusterInfo{
		CollectionTime: time.Now(),
	}

	// Get cluster version
	version, err := c.clientset.Discovery().ServerVersion()
	if err != nil {
		logrus.Warnf("Failed to get cluster version: %v", err)
		info.ClusterVersion = "unknown"
	} else {
		info.ClusterVersion = fmt.Sprintf("%s.%s", version.Major, version.Minor)
	}

	// Collect nodes
	if c.config.Modules.Nodes {
		if nodes, err := c.collectNodes(ctx); err != nil {
			logrus.Errorf("Failed to collect nodes: %v", err)
		} else {
			info.Nodes = nodes
			info.Summary.TotalNodes = len(nodes)
		}
	}

	// Collect namespaces
	if c.config.Modules.Namespaces {
		if namespaces, err := c.collectNamespaces(ctx, targetNamespace); err != nil {
			logrus.Errorf("Failed to collect namespaces: %v", err)
		} else {
			info.Namespaces = namespaces
			info.Summary.TotalNamespaces = len(namespaces)
		}
	}

	// Collect pods
	if c.config.Modules.Pods {
		if pods, err := c.collectPods(ctx, targetNamespace); err != nil {
			logrus.Errorf("Failed to collect pods: %v", err)
		} else {
			info.Pods = pods
			info.Summary.TotalPods = len(pods)
		}
	}

	// Collect services
	if c.config.Modules.Services {
		if services, err := c.collectServices(ctx, targetNamespace); err != nil {
			logrus.Errorf("Failed to collect services: %v", err)
		} else {
			info.Services = services
			info.Summary.TotalServices = len(services)
		}
	}

	// Collect network policies
	if c.config.Modules.NetworkPolicies {
		if policies, err := c.collectNetworkPolicies(ctx, targetNamespace); err != nil {
			logrus.Errorf("Failed to collect network policies: %v", err)
		} else {
			info.NetworkPolicies = policies
		}
	}

	// Collect RBAC
	if c.config.Modules.RBAC {
		if rbac, err := c.collectRBAC(ctx, targetNamespace); err != nil {
			logrus.Errorf("Failed to collect RBAC: %v", err)
		} else {
			info.RBAC = *rbac
		}
	}

	// Perform security analysis
	if c.config.SecurityFocus {
		// Security analysis is now handled by the rule engine in main
		// This will be replaced by rule engine evaluation
		logrus.Debug("Security analysis will be performed by rule engine")
		info.Summary.SecurityFindings = 0
	}

	logrus.Info("Collection completed")
	return info, nil
}

func (c *ClusterInfo) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

func (c *ClusterInfo) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}
