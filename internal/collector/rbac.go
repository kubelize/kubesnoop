package collector

import (
	"context"

	"github.com/sirupsen/logrus"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *Collector) collectNetworkPolicies(ctx context.Context, targetNamespace string) ([]NetworkPolicyInfo, error) {
	var policies *networkingv1.NetworkPolicyList
	var err error

	if targetNamespace != "" {
		policies, err = c.clientset.NetworkingV1().NetworkPolicies(targetNamespace).List(ctx, metav1.ListOptions{})
	} else {
		policies, err = c.clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, err
	}

	var policyInfos []NetworkPolicyInfo
	for _, policy := range policies.Items {
		// Skip policies in excluded namespaces
		if c.shouldExcludeNamespace(policy.Namespace) {
			continue
		}

		policyInfo := NetworkPolicyInfo{
			Name:      policy.Name,
			Namespace: policy.Namespace,
			Spec:      policy.Spec,
		}

		policyInfos = append(policyInfos, policyInfo)
	}

	logrus.Debugf("Collected %d network policies", len(policyInfos))
	return policyInfos, nil
}

func (c *Collector) collectRBAC(ctx context.Context, targetNamespace string) (*RBACInfo, error) {
	rbacInfo := &RBACInfo{}

	// Collect cluster roles
	clusterRoles, err := c.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("Failed to collect cluster roles: %v", err)
	} else {
		rbacInfo.ClusterRoles = clusterRoles.Items
	}

	// Collect cluster role bindings
	clusterRoleBindings, err := c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("Failed to collect cluster role bindings: %v", err)
	} else {
		rbacInfo.ClusterRoleBindings = clusterRoleBindings.Items
	}

	// Collect roles (namespace-scoped)
	var roles *rbacv1.RoleList
	if targetNamespace != "" {
		roles, err = c.clientset.RbacV1().Roles(targetNamespace).List(ctx, metav1.ListOptions{})
	} else {
		roles, err = c.clientset.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	}
	
	if err != nil {
		logrus.Errorf("Failed to collect roles: %v", err)
	} else {
		for _, role := range roles.Items {
			if !c.shouldExcludeNamespace(role.Namespace) {
				rbacInfo.Roles = append(rbacInfo.Roles, role)
			}
		}
	}

	// Collect role bindings (namespace-scoped)
	var roleBindings *rbacv1.RoleBindingList
	if targetNamespace != "" {
		roleBindings, err = c.clientset.RbacV1().RoleBindings(targetNamespace).List(ctx, metav1.ListOptions{})
	} else {
		roleBindings, err = c.clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	}
	
	if err != nil {
		logrus.Errorf("Failed to collect role bindings: %v", err)
	} else {
		for _, binding := range roleBindings.Items {
			if !c.shouldExcludeNamespace(binding.Namespace) {
				rbacInfo.RoleBindings = append(rbacInfo.RoleBindings, binding)
			}
		}
	}

	// Collect service accounts
	var serviceAccounts *corev1.ServiceAccountList
	if targetNamespace != "" {
		serviceAccounts, err = c.clientset.CoreV1().ServiceAccounts(targetNamespace).List(ctx, metav1.ListOptions{})
	} else {
		serviceAccounts, err = c.clientset.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	}
	
	if err != nil {
		logrus.Errorf("Failed to collect service accounts: %v", err)
	} else {
		for _, sa := range serviceAccounts.Items {
			if !c.shouldExcludeNamespace(sa.Namespace) {
				rbacInfo.ServiceAccounts = append(rbacInfo.ServiceAccounts, sa)
			}
		}
	}

	logrus.Debugf("Collected RBAC: %d cluster roles, %d cluster role bindings, %d roles, %d role bindings, %d service accounts",
		len(rbacInfo.ClusterRoles), len(rbacInfo.ClusterRoleBindings), len(rbacInfo.Roles), 
		len(rbacInfo.RoleBindings), len(rbacInfo.ServiceAccounts))

	return rbacInfo, nil
}
