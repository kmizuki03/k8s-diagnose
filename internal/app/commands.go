package app

import (
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

func (runner *Runner) renderCommandGroup(commands [][]string) {
	if !runner.Config.ShowCmd || runner.Config.Output != "text" {
		return
	}
	commands = uniqueArgv(commands)
	if len(commands) == 0 {
		return
	}
	for _, command := range commands {
		runner.Console.Command(shellDisplay(command))
	}
}

func (runner *Runner) renderCommandsForKeys(snapshot *kube.Snapshot, keys ...string) {
	if snapshot == nil {
		return
	}
	runner.renderCommandGroup(kube.KubectlCommandsForKeys(runner.Config, snapshot.Statuses, keys...))
}

func (runner *Runner) renderCommandsForFinding(snapshot *kube.Snapshot, finding model.Finding) {
	commands := runner.commandsForResource(finding.Resource)
	if len(commands) == 0 && snapshot != nil && runner.Registry != nil {
		if metadata, ok := runner.Registry.MetadataFor(finding.RuleID); ok {
			keys := append(append([]string{}, metadata.Required...), metadata.Optional...)
			commands = kube.KubectlCommandsForKeys(runner.Config, snapshot.Statuses, keys...)
		}
	}
	if len(commands) == 0 && snapshot != nil && finding.RuleID == "unused" {
		commands = kube.KubectlCommandsForKeys(runner.Config, snapshot.Statuses,
			"pods", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs",
			"ingresses", "configmaps", "secrets", "pvcs", "serviceaccounts")
	}
	runner.renderCommandGroup(commands)
}

func (runner *Runner) renderPendingKubectlCommands() {
	commands := runner.kubectlCmds
	runner.kubectlCmds = nil
	runner.renderCommandGroup(commands)
}

func (runner *Runner) commandsForResource(resource string) [][]string {
	parts := strings.Split(resource, "/")
	if len(parts) < 2 {
		return nil
	}
	kind := parts[0]
	if kind == "Probe" && len(parts) >= 3 {
		return [][]string{runner.objectCommand("pod", parts[1], parts[2])}
	}
	if kind == "ControlPlane" {
		switch parts[1] {
		case "readyz", "livez":
			return [][]string{kube.KubectlCommand(runner.Config, "get", "--raw=/"+parts[1]+"?verbose")}
		}
		return nil
	}

	type commandTarget struct {
		resource   string
		namespaced bool
	}
	targets := map[string]commandTarget{
		"Pod": {"pod", true}, "Deployment": {"deployment", true}, "ReplicaSet": {"replicaset", true},
		"StatefulSet": {"statefulset", true}, "DaemonSet": {"daemonset", true}, "Job": {"job", true},
		"CronJob": {"cronjob", true}, "HPA": {"horizontalpodautoscaler", true},
		"HorizontalPodAutoscaler": {"horizontalpodautoscaler", true}, "Service": {"service", true},
		"EndpointSlice": {"endpointslice", true}, "Endpoints": {"endpoints", true}, "Ingress": {"ingress", true},
		"Secret": {"secret", true}, "ConfigMap": {"configmap", true}, "PVC": {"persistentvolumeclaim", true},
		"PersistentVolumeClaim": {"persistentvolumeclaim", true}, "ServiceAccount": {"serviceaccount", true},
		"NetworkPolicy": {"networkpolicy", true}, "ResourceQuota": {"resourcequota", true},
		"LimitRange": {"limitrange", true}, "PDB": {"poddisruptionbudget", true},
		"PodDisruptionBudget": {"poddisruptionbudget", true}, "Node": {"node", false},
		"Namespace": {"namespace", false}, "PV": {"persistentvolume", false},
		"PersistentVolume": {"persistentvolume", false}, "StorageClass": {"storageclass", false},
		"PriorityClass": {"priorityclass", false}, "RuntimeClass": {"runtimeclass", false},
		"APIService": {"apiservice", false}, "CRD": {"customresourcedefinition", false},
		"CustomResourceDefinition":       {"customresourcedefinition", false},
		"ValidatingWebhookConfiguration": {"validatingwebhookconfiguration", false},
		"MutatingWebhookConfiguration":   {"mutatingwebhookconfiguration", false},
	}
	target, ok := targets[kind]
	if !ok {
		return nil
	}
	if target.namespaced {
		if len(parts) < 3 {
			return nil
		}
		return [][]string{runner.objectCommand(target.resource, parts[1], parts[2])}
	}
	return [][]string{runner.objectCommand(target.resource, "", parts[1])}
}

func (runner *Runner) objectCommand(resource, namespace, name string) []string {
	args := []string{"get", resource, name}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	args = append(args, "-o", "json")
	return kube.KubectlCommand(runner.Config, args...)
}

func uniqueArgv(commands [][]string) [][]string {
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

func shellDisplay(args []string) string {
	quoted := make([]string, len(args))
	for index, value := range args {
		if value != "" && !strings.ContainsAny(value, " \t\n'\"\\$`;&|<>()[]{}*?!") {
			quoted[index] = value
		} else {
			quoted[index] = "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
		}
	}
	return strings.Join(quoted, " ")
}
