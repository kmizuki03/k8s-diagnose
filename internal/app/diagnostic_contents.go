package app

import (
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

func (runner *Runner) diagnosticItems(snapshot *kube.Snapshot, state *model.State) []console.DiagnosticItem {
	if state == nil {
		return nil
	}
	items := make([]console.DiagnosticItem, 0, len(state.Checks))
	for _, original := range state.Checks {
		check := original
		optionalKey, supplemental := diagnosticOptionalKey(check.ID)
		if supplemental {
			check.Description = "追加情報として" + diagnosticInputLabel(optionalKey) + "を取得"
		}
		check.Reason = friendlyDiagnosticReason(check.Reason)
		commands := runner.commandsForDiagnosticCheck(snapshot, original, optionalKey)
		displayCommands := make([]string, 0, len(commands))
		for _, command := range uniqueArgv(commands) {
			displayCommands = append(displayCommands, shellDisplay(command))
		}
		items = append(items, console.DiagnosticItem{
			Check: check, Findings: findingsForDiagnosticCheck(original, state.Findings),
			Commands: displayCommands, Supplemental: supplemental,
		})
	}
	return items
}

func (runner *Runner) commandsForDiagnosticCheck(snapshot *kube.Snapshot, check model.Check, optionalKey string) [][]string {
	if strings.HasPrefix(check.ID, "logs/") {
		return runner.logCommandsForDiagnosticCheck(check.ID)
	}
	if snapshot == nil {
		return nil
	}
	if optionalKey != "" {
		return kube.KubectlCommandsForKeys(runner.Config, snapshot.Statuses, optionalKey)
	}
	if strings.HasPrefix(check.ID, "unused/") {
		return kube.KubectlCommandsForKeys(runner.Config, snapshot.Statuses, strings.TrimPrefix(check.ID, "unused/"))
	}
	if runner.Registry == nil {
		return nil
	}
	metadata, ok := runner.Registry.MetadataFor(check.ID)
	if !ok {
		return nil
	}
	return kube.KubectlCommandsForKeys(runner.Config, snapshot.Statuses, metadata.Required...)
}

func (runner *Runner) logCommandsForDiagnosticCheck(checkID string) [][]string {
	parts := strings.Split(checkID, "/")
	if len(parts) != 4 || parts[0] != "logs" {
		return nil
	}
	namespace, pod, source := parts[1], parts[2], parts[3]
	wantPrevious := source == "previous"
	commands := [][]string{}
	for _, command := range runner.kubectlCmds {
		logsIndex := -1
		for index, value := range command {
			if value == "logs" {
				logsIndex = index
				break
			}
		}
		if logsIndex < 0 || logsIndex+1 >= len(command) || command[logsIndex+1] != pod {
			continue
		}
		commandNamespace := ""
		previous := false
		for index := logsIndex + 2; index < len(command); index++ {
			switch command[index] {
			case "-n", "--namespace":
				if index+1 < len(command) {
					commandNamespace = command[index+1]
					index++
				}
			case "--previous":
				previous = true
			}
		}
		if commandNamespace == namespace && previous == wantPrevious {
			commands = append(commands, command)
		}
	}
	return uniqueArgv(commands)
}

func findingsForDiagnosticCheck(check model.Check, findings []model.Finding) []model.Finding {
	if _, supplemental := diagnosticOptionalKey(check.ID); supplemental {
		return nil
	}
	if strings.HasPrefix(check.ID, "logs/") {
		parts := strings.Split(check.ID, "/")
		if len(parts) != 4 {
			return nil
		}
		resource := "Pod/" + parts[1] + "/" + parts[2]
		source := parts[3]
		result := []model.Finding{}
		for _, finding := range findings {
			if finding.RuleID == "logs" && finding.Resource == resource && (finding.StableKey == source || strings.HasPrefix(finding.StableKey, source+"/")) {
				result = append(result, finding)
			}
		}
		return result
	}
	if strings.HasPrefix(check.ID, "unused/") {
		collection := strings.TrimPrefix(check.ID, "unused/")
		kindToCollection := map[string]string{
			"ConfigMap": "configmaps", "Secret": "secrets",
			"PVC": "pvcs", "PersistentVolumeClaim": "pvcs", "ServiceAccount": "serviceaccounts",
		}
		result := []model.Finding{}
		for _, finding := range findings {
			kind := strings.SplitN(finding.Resource, "/", 2)[0]
			if finding.RuleID == "unused" && kindToCollection[kind] == collection {
				result = append(result, finding)
			}
		}
		return result
	}
	result := []model.Finding{}
	for _, finding := range findings {
		if finding.RuleID == check.ID && finding.Code != "K8S.API.PARTIAL_UNAVAILABLE" {
			result = append(result, finding)
		}
	}
	return result
}

func diagnosticOptionalKey(checkID string) (string, bool) {
	const marker = "/optional/"
	index := strings.Index(checkID, marker)
	if index < 0 || index+len(marker) >= len(checkID) {
		return "", false
	}
	return checkID[index+len(marker):], true
}

func friendlyDiagnosticReason(reason string) string {
	parts := strings.Split(reason, "; ")
	for index, part := range parts {
		key, detail, found := strings.Cut(part, "=")
		if !found || !knownDiagnosticInput(key) {
			continue
		}
		parts[index] = diagnosticInputLabel(key) + "を取得できません。原因: " + detail
	}
	return strings.Join(parts, " / ")
}

func knownDiagnosticInput(key string) bool {
	_, ok := diagnosticInputLabels[key]
	return ok
}

func diagnosticInputLabel(key string) string {
	if label, ok := diagnosticInputLabels[key]; ok {
		return label
	}
	return "Kubernetes API情報「" + key + "」"
}

// diagnosticInputLabels maps collector input keys to their display labels. The
// keys are Kubernetes resource names that must stay identical to the collector
// keys, so "secrets" refers to the Secret resource kind and the value is a
// screen label. No credential is stored here.
var diagnosticInputLabels = map[string]string{ // #nosec G101 -- Kubernetes resource names and display labels, not credentials.
	"pods":               "Pod一覧",
	"all_pods":           "クラスタ内のPod一覧",
	"nodes":              "Node一覧",
	"node_leases":        "Node Lease一覧",
	"services":           "Service一覧",
	"endpoints":          "Endpoints一覧（互換フォールバック）",
	"endpoint_slices":    "EndpointSlice一覧",
	"pvcs":               "PVC一覧",
	"pvs":                "PersistentVolume一覧",
	"configmaps":         "ConfigMap一覧",
	"secrets":            "Secret一覧",
	"serviceaccounts":    "ServiceAccount一覧",
	"events":             "Event一覧",
	"storageclasses":     "StorageClass一覧",
	"ingressclasses":     "IngressClass一覧",
	"pod_metrics":        "Podメトリクス",
	"node_metrics":       "Nodeメトリクス",
	"readyz":             "API Server readyz",
	"livez":              "API Server livez",
	"deployments":        "Deployment一覧",
	"statefulsets":       "StatefulSet一覧",
	"daemonsets":         "DaemonSet一覧",
	"replicasets":        "ReplicaSet一覧",
	"jobs":               "Job一覧",
	"cronjobs":           "CronJob一覧",
	"ingresses":          "Ingress一覧",
	"networkpolicies":    "NetworkPolicy一覧",
	"resourcequotas":     "ResourceQuota一覧",
	"limitranges":        "LimitRange一覧",
	"pdbs":               "PodDisruptionBudget一覧",
	"priorityclasses":    "PriorityClass一覧",
	"runtimeclasses":     "RuntimeClass一覧",
	"validatingwebhooks": "ValidatingWebhookConfiguration一覧",
	"mutatingwebhooks":   "MutatingWebhookConfiguration一覧",
	"apiservices":        "APIService一覧",
	"crds":               "CustomResourceDefinition一覧",
	"namespaces":         "Namespace一覧",
}
