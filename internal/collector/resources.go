package collector

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (c *Collector) collectNodes(ctx context.Context) ([]NodeInfo, error) {
	nodes, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var nodeInfos []NodeInfo
	for _, node := range nodes.Items {
		nodeInfo := NodeInfo{
			Name:       node.Name,
			Labels:     node.Labels,
			Taints:     node.Spec.Taints,
			Conditions: node.Status.Conditions,
		}

		// Extract version and OS info
		nodeInfo.Version = node.Status.NodeInfo.KubeletVersion
		nodeInfo.OS = node.Status.NodeInfo.OperatingSystem
		nodeInfo.Kernel = node.Status.NodeInfo.KernelVersion
		nodeInfo.Container = node.Status.NodeInfo.ContainerRuntimeVersion

		nodeInfos = append(nodeInfos, nodeInfo)
	}

	logrus.Debugf("Collected %d nodes", len(nodeInfos))
	return nodeInfos, nil
}

func (c *Collector) collectNamespaces(ctx context.Context, targetNamespace string) ([]NamespaceInfo, error) {
	var namespaces *corev1.NamespaceList
	var err error

	if targetNamespace != "" {
		// Get specific namespace
		ns, err := c.clientset.CoreV1().Namespaces().Get(ctx, targetNamespace, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		namespaces = &corev1.NamespaceList{
			Items: []corev1.Namespace{*ns},
		}
	} else {
		// Get all namespaces
		namespaces, err = c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
	}

	var namespaceInfos []NamespaceInfo
	for _, ns := range namespaces.Items {
		// Skip excluded namespaces
		if c.shouldExcludeNamespace(ns.Name) {
			continue
		}

		namespaceInfo := NamespaceInfo{
			Name:        ns.Name,
			Labels:      ns.Labels,
			Annotations: ns.Annotations,
			Phase:       ns.Status.Phase,
		}

		namespaceInfos = append(namespaceInfos, namespaceInfo)
	}

	logrus.Debugf("Collected %d namespaces", len(namespaceInfos))
	return namespaceInfos, nil
}

func (c *Collector) collectPods(ctx context.Context, targetNamespace string) ([]PodInfo, error) {
	var pods *corev1.PodList
	var err error

	if targetNamespace != "" {
		pods, err = c.clientset.CoreV1().Pods(targetNamespace).List(ctx, metav1.ListOptions{})
	} else {
		pods, err = c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, err
	}

	var podInfos []PodInfo
	for _, pod := range pods.Items {
		// Skip pods in excluded namespaces
		if c.shouldExcludeNamespace(pod.Namespace) {
			continue
		}

		podInfo := PodInfo{
			Name:           pod.Name,
			Namespace:      pod.Namespace,
			Labels:         pod.Labels,
			Annotations:    pod.Annotations,
			ServiceAccount: pod.Spec.ServiceAccountName,
			Phase:          pod.Status.Phase,
		}

		// Security context
		if pod.Spec.SecurityContext != nil {
			podInfo.SecurityContext = pod.Spec.SecurityContext
			podInfo.HostNetwork = pod.Spec.HostNetwork
			podInfo.HostPID = pod.Spec.HostPID
			podInfo.HostIPC = pod.Spec.HostIPC
		}

		// Container information
		for _, container := range pod.Spec.Containers {
			containerInfo := ContainerInfo{
				Name:            container.Name,
				Image:           container.Image,
				SecurityContext: container.SecurityContext,
				Resources:       container.Resources,
				Ports:           container.Ports,
			}
			podInfo.Containers = append(podInfo.Containers, containerInfo)
		}

		// Owner reference
		if len(pod.OwnerReferences) > 0 {
			owner := pod.OwnerReferences[0]
			podInfo.Owner = owner.Kind + "/" + owner.Name
		}

		podInfos = append(podInfos, podInfo)
	}

	logrus.Debugf("Collected %d pods", len(podInfos))
	return podInfos, nil
}

func (c *Collector) collectServices(ctx context.Context, targetNamespace string) ([]ServiceInfo, error) {
	var services *corev1.ServiceList
	var err error

	if targetNamespace != "" {
		services, err = c.clientset.CoreV1().Services(targetNamespace).List(ctx, metav1.ListOptions{})
	} else {
		services, err = c.clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, err
	}

	var serviceInfos []ServiceInfo
	for _, svc := range services.Items {
		// Skip services in excluded namespaces
		if c.shouldExcludeNamespace(svc.Namespace) {
			continue
		}

		serviceInfo := ServiceInfo{
			Name:        svc.Name,
			Namespace:   svc.Namespace,
			Type:        svc.Spec.Type,
			Ports:       svc.Spec.Ports,
			Selector:    svc.Spec.Selector,
			ExternalIPs: svc.Spec.ExternalIPs,
		}

		serviceInfos = append(serviceInfos, serviceInfo)
	}

	logrus.Debugf("Collected %d services", len(serviceInfos))
	return serviceInfos, nil
}

func (c *Collector) shouldExcludeNamespace(namespace string) bool {
	for _, excluded := range c.config.ExcludeNamespaces {
		if excluded == namespace {
			return true
		}
		// Support wildcard matching
		if strings.Contains(excluded, "*") {
			excluded = strings.ReplaceAll(excluded, "*", "")
			if strings.Contains(namespace, excluded) {
				return true
			}
		}
	}
	return false
}
