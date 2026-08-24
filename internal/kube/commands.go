package kube

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
)

type kubectlCommandSpec struct {
	key        string
	resource   string
	namespaced bool
	namespace  string
	rawPath    func(config.Config) string
}

// KubectlCommand adds the same target selection and request timeout used by
// the Go client. The returned argv is display-only unless an explicit caller
// chooses to execute it.
func KubectlCommand(cfg config.Config, args ...string) []string {
	result := []string{"kubectl"}
	if cfg.Kubeconfig != "" {
		result = append(result, "--kubeconfig", cfg.Kubeconfig)
	}
	if cfg.Context != "" {
		result = append(result, "--context", cfg.Context)
	}
	if cfg.RequestTimeout > 0 {
		result = append(result, "--request-timeout="+strconv.Itoa(cfg.RequestTimeout)+"s")
	}
	return append(result, args...)
}

// KubectlCommandsForKeys returns commands only for the requested collection
// keys. It is used by the text renderer to place each command next to the
// diagnostic item it supports instead of printing one large list up front.
func KubectlCommandsForKeys(cfg config.Config, statuses map[string]FetchStatus, keys ...string) [][]string {
	selected := make(map[string]FetchStatus, len(keys))
	for _, key := range keys {
		if status, attempted := statuses[key]; attempted {
			selected[key] = status
		}
	}
	return kubectlCommands(cfg, selected)
}

func kubectlCommands(cfg config.Config, statuses map[string]FetchStatus) [][]string {
	if len(statuses) == 0 {
		return nil
	}
	commands := [][]string{}
	specs := []kubectlCommandSpec{
		{key: "pods", resource: "pods", namespaced: true},
		{key: "all_pods", resource: "pods", namespaced: true, namespace: "*"},
		{key: "nodes", resource: "nodes"},
		{key: "node_leases", resource: "leases.coordination.k8s.io", namespaced: true, namespace: "kube-node-lease"},
		{key: "services", resource: "services", namespaced: true},
		{key: "endpoints", resource: "endpoints", namespaced: true},
		{key: "endpoint_slices", resource: "endpointslices.discovery.k8s.io", namespaced: true},
		{key: "pvcs", resource: "persistentvolumeclaims", namespaced: true},
		{key: "pvs", resource: "persistentvolumes"},
		{key: "configmaps", resource: "configmaps", namespaced: true},
		{key: "secrets", resource: "secrets", namespaced: true},
		{key: "serviceaccounts", resource: "serviceaccounts", namespaced: true},
		{key: "namespaces", resource: "namespaces"},
		{key: "events", resource: "events", namespaced: true},
		{key: "resourcequotas", resource: "resourcequotas", namespaced: true},
		{key: "limitranges", resource: "limitranges", namespaced: true},
		{key: "deployments", resource: "deployments.apps", namespaced: true},
		{key: "statefulsets", resource: "statefulsets.apps", namespaced: true},
		{key: "daemonsets", resource: "daemonsets.apps", namespaced: true},
		{key: "replicasets", resource: "replicasets.apps", namespaced: true},
		{key: "jobs", resource: "jobs.batch", namespaced: true},
		{key: "cronjobs", resource: "cronjobs.batch", namespaced: true},
		{key: "hpas", resource: "horizontalpodautoscalers.autoscaling", namespaced: true},
		{key: "ingresses", resource: "ingresses.networking.k8s.io", namespaced: true},
		{key: "ingressclasses", resource: "ingressclasses.networking.k8s.io"},
		{key: "networkpolicies", resource: "networkpolicies.networking.k8s.io", namespaced: true},
		{key: "validatingwebhooks", resource: "validatingwebhookconfigurations.admissionregistration.k8s.io"},
		{key: "mutatingwebhooks", resource: "mutatingwebhookconfigurations.admissionregistration.k8s.io"},
		{key: "storageclasses", resource: "storageclasses.storage.k8s.io"},
		{key: "pdbs", resource: "poddisruptionbudgets.policy", namespaced: true},
		{key: "priorityclasses", resource: "priorityclasses.scheduling.k8s.io"},
		{key: "runtimeclasses", resource: "runtimeclasses.node.k8s.io"},
		{key: "node_metrics", rawPath: func(config.Config) string { return "/apis/metrics.k8s.io/v1beta1/nodes" }},
		{key: "pod_metrics", rawPath: podMetricsPath},
		{key: "apiservices", resource: "apiservices.apiregistration.k8s.io"},
		{key: "crds", resource: "customresourcedefinitions.apiextensions.k8s.io"},
		{key: "gatewayclasses", resource: "gatewayclasses.gateway.networking.k8s.io"},
		{key: "gateways", resource: "gateways.gateway.networking.k8s.io", namespaced: true},
		{key: "httproutes", resource: "httproutes.gateway.networking.k8s.io", namespaced: true},
		{key: "readyz", rawPath: func(config.Config) string { return "/readyz?verbose" }},
		{key: "livez", rawPath: func(config.Config) string { return "/livez?verbose" }},
	}
	for _, spec := range specs {
		if _, attempted := statuses[spec.key]; !attempted {
			continue
		}
		if spec.rawPath != nil {
			commands = append(commands, KubectlCommand(cfg, "get", "--raw="+spec.rawPath(cfg)))
			continue
		}
		args := []string{"get", spec.resource}
		namespace := cfg.Namespace
		if spec.namespace == "*" {
			namespace = ""
		} else if spec.namespace != "" {
			namespace = spec.namespace
		}
		args = appendScope(args, namespace, spec.namespaced)
		if cfg.PageSize > 0 {
			args = append(args, "--chunk-size="+fmt.Sprint(cfg.PageSize))
		}
		args = append(args, "-o", "json")
		commands = append(commands, KubectlCommand(cfg, args...))
	}
	return uniqueCommands(commands)
}

func appendScope(args []string, namespace string, namespaced bool) []string {
	if !namespaced {
		return args
	}
	if namespace == "" {
		return append(args, "-A")
	}
	return append(args, "-n", namespace)
}

func podMetricsPath(cfg config.Config) string {
	if cfg.Namespace == "" {
		return "/apis/metrics.k8s.io/v1beta1/pods"
	}
	return "/apis/metrics.k8s.io/v1beta1/namespaces/" + url.PathEscape(cfg.Namespace) + "/pods"
}

func uniqueCommands(commands [][]string) [][]string {
	seen := map[string]struct{}{}
	result := make([][]string, 0, len(commands))
	for _, command := range commands {
		key := strings.Join(command, "\x00")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, command)
	}
	return result
}
