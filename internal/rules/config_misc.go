package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type ConfigRiskRule struct{}

func (ConfigRiskRule) Metadata() Metadata {
	return Metadata{ID: "config-risks", Section: "構成リスク", Description: "イメージタグ・リソース要求・Probe設定", Required: []string{"pods"}, Permissions: namespaced("", "pods"), Modes: []string{"all", "triage", "select"}}
}

func (ConfigRiskRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		jobPod := podOwnedByJob(pod)
		images := []struct{ name, image string }{}
		for _, container := range pod.Spec.InitContainers {
			images = append(images, struct{ name, image string }{container.Name, container.Image})
		}
		for _, container := range pod.Spec.Containers {
			images = append(images, struct{ name, image string }{container.Name, container.Image})
		}
		for _, container := range pod.Spec.EphemeralContainers {
			images = append(images, struct{ name, image string }{container.Name, container.Image})
		}
		for _, value := range images {
			if value.image == "" || strings.Contains(value.image, "@") {
				continue
			}
			leaf := value.image
			if index := strings.LastIndex(leaf, "/"); index >= 0 {
				leaf = leaf[index+1:]
			}
			reason := ""
			if strings.HasSuffix(strings.ToLower(leaf), ":latest") {
				reason = "LatestTag"
			} else if !strings.Contains(leaf, ":") {
				reason = "UntaggedImage"
			}
			if reason == "" {
				continue
			}
			description := fmt.Sprintf("イメージ %q にタグが指定されていません", value.image)
			if reason == "LatestTag" {
				description = fmt.Sprintf("イメージ %q に可変タグ :latest が指定されています", value.image)
			}
			result = append(result, model.NewFinding(model.Candidate, "K8S.CONFIG.IMAGE_TAG_RISK", "構成リスク", ref("Pod", pod.Namespace, pod.Name), reason, value.name+"/"+reason, fmt.Sprintf("Pod %s のコンテナ %q では、%s", shortRef(pod.Namespace, pod.Name), value.name, description), 45))
		}
		workloadContainers := append([]corev1.Container{}, pod.Spec.Containers...)
		for _, container := range pod.Spec.InitContainers {
			if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
				workloadContainers = append(workloadContainers, container)
			}
		}
		for _, container := range workloadContainers {
			missing := []string{}
			podRequests := corev1.ResourceList(nil)
			if pod.Spec.Resources != nil {
				podRequests = pod.Spec.Resources.Requests
			}
			for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
				containerQuantity, containerDefined := container.Resources.Requests[name]
				podQuantity, podDefined := podRequests[name]
				if (!containerDefined || containerQuantity.Sign() <= 0) && (!podDefined || podQuantity.Sign() <= 0) {
					missing = append(missing, string(name))
				}
			}
			if len(missing) > 0 {
				result = append(result, model.NewFinding(model.Candidate, "K8S.CONFIG.REQUESTS_MISSING", "構成リスク", ref("Pod", pod.Namespace, pod.Name), "RequestsMissing", container.Name+"/requests", fmt.Sprintf("Pod %s のコンテナ %q では、resources.requests に %s が設定されていません", shortRef(pod.Namespace, pod.Name), container.Name, strings.Join(missing, "、")), 40))
			}
			if !jobPod && container.LivenessProbe == nil {
				result = append(result, model.NewFinding(model.Candidate, "K8S.CONFIG.LIVENESS_PROBE_MISSING", "構成リスク", ref("Pod", pod.Namespace, pod.Name), "LivenessProbeMissing", container.Name+"/liveness", fmt.Sprintf("Pod %s のコンテナ %q には、livenessProbe が設定されていません", shortRef(pod.Namespace, pod.Name), container.Name), 35))
			}
		}
	}
	return result
}

type NamespaceRule struct{}

func (NamespaceRule) Metadata() Metadata {
	return Metadata{ID: "namespaces", Section: "Namespace", Description: "Namespaceの削除状態", Required: []string{"namespaces"}, Permissions: cluster("", "namespaces"), Modes: []string{"all", "triage"}}
}

func (NamespaceRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.Namespaces {
		namespace := &snapshot.Namespaces[i]
		if namespace.Status.Phase != corev1.NamespaceTerminating || namespace.DeletionTimestamp == nil {
			continue
		}
		minutes := int(elapsedSince(snapshot, namespace.DeletionTimestamp.Time).Minutes())
		if minutes < 10 {
			continue
		}
		result = append(result, model.NewFinding(model.Warning, "K8S.NAMESPACE.TERMINATING_STUCK", "Namespace", ref("Namespace", "", namespace.Name), "Terminating", "terminating", fmt.Sprintf("Namespace %s の削除処理が完了せず、Terminating 状態が %d分間続いています", namespace.Name, minutes), 75, model.Evidence{Kind: "namespace", Key: "deletionTimestamp", Value: namespace.DeletionTimestamp.String()}))
	}
	return result
}

type CRDRule struct{}

func (CRDRule) Metadata() Metadata {
	return Metadata{ID: "crds", Section: "CRD", Description: "CRDのEstablished・NamesAccepted条件", Required: []string{"crds"}, Permissions: cluster("apiextensions.k8s.io", "customresourcedefinitions"), Modes: []string{"all", "triage"}}
}

func (CRDRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.CustomResourceDefs {
		item := &snapshot.CustomResourceDefs[i]
		conditions, _, _ := unstructured.NestedSlice(item.Object, "status", "conditions")
		for _, raw := range conditions {
			condition, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			typeName, status := objectStringField(condition, "type"), objectStringField(condition, "status")
			bad := typeName == "Established" && status != "True" || typeName == "NamesAccepted" && status == "False"
			if !bad {
				continue
			}
			reason := objectStringField(condition, "reason")
			result = append(result, model.NewFinding(model.Warning, "K8S.CRD.CONDITION", "CRD", ref("CustomResourceDefinition", "", item.GetName()), reason, typeName, conditionStateMessage("CRD", item.GetName(), typeName, status, reason), 85, model.Evidence{Kind: "condition", Key: typeName, Value: objectStringField(condition, "message")}))
		}
	}
	return result
}
