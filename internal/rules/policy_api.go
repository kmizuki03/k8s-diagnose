package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

type QuotaRule struct{}

func (QuotaRule) Metadata() Metadata {
	return Metadata{ID: "resource-quota", Section: "ResourceQuota", Description: "ResourceQuotaの使用率", Required: []string{"resourcequotas"}, Permissions: namespaced("", "resourcequotas"), Modes: []string{"all", "triage"}}
}

func (QuotaRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.ResourceQuotas {
		quota := &snapshot.ResourceQuotas[i]
		for name, hard := range quota.Status.Hard {
			used, ok := quota.Status.Used[name]
			if !ok || hard.Sign() <= 0 {
				continue
			}
			ratio := quantityRatio(used, hard)
			if ratio < 90 {
				continue
			}
			severity, confidence := model.Candidate, 55
			if used.Cmp(hard) >= 0 {
				severity, confidence = model.Warning, 85
			}
			result = append(result, model.NewFinding(severity, "K8S.RESOURCE_QUOTA.HIGH_USAGE", "ResourceQuota", ref("ResourceQuota", quota.Namespace, quota.Name), string(name), string(name), fmt.Sprintf("ResourceQuota %s のリソース %q は、上限 %s のうち %s を使用しています（%d%%）", shortRef(quota.Namespace, quota.Name), name, hard.String(), used.String(), ratio), confidence))
		}
	}
	return result
}

func quantityRatio(used, hard resource.Quantity) int {
	denominator := hard.AsApproximateFloat64()
	if denominator <= 0 {
		return 0
	}
	return int(used.AsApproximateFloat64() * 100 / denominator)
}

type PDBRule struct{}

func (PDBRule) Metadata() Metadata {
	permissions := namespaced("policy", "poddisruptionbudgets")
	permissions = append(permissions, namespaced("", "pods")...)
	return Metadata{ID: "pdb", Section: "ワークロード（Deploymentなど）", Description: "PodDisruptionBudgetの保護対象と退避余力", Required: []string{"pdbs"}, Optional: []string{"pods"}, Permissions: permissions, Modes: []string{"all", "triage"}}
}

func (PDBRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	podIndex := indexPodsByNamespace(snapshot.Pods)
	for i := range snapshot.PodDisruptionBudgets {
		pdb := &snapshot.PodDisruptionBudgets[i]
		if !statusGenerationCurrent(pdb.Generation, pdb.Status.ObservedGeneration) {
			continue
		}
		resource := ref("PodDisruptionBudget", pdb.Namespace, pdb.Name)
		if finding, ok := pdbProtectsNothing(pdb, podIndex, snapshot, resource); ok {
			result = append(result, finding)
			continue
		}
		if pdb.Status.CurrentHealthy < pdb.Status.DesiredHealthy {
			result = append(result, model.NewFinding(model.Warning, "K8S.PDB.HEALTH_BELOW_DESIRED", "ワークロード（Deploymentなど）", resource, "HealthBelowDesired", "health", fmt.Sprintf("PDB %s では、正常なPodが %d個しかなく、必要な %d個を下回っています", shortRef(pdb.Namespace, pdb.Name), pdb.Status.CurrentHealthy, pdb.Status.DesiredHealthy), 85,
				model.Evidence{Kind: "status", Key: "currentHealthy", Value: fmt.Sprint(pdb.Status.CurrentHealthy)},
				model.Evidence{Kind: "status", Key: "desiredHealthy", Value: fmt.Sprint(pdb.Status.DesiredHealthy)}))
		} else if pdb.Status.ExpectedPods > 0 && pdb.Status.DisruptionsAllowed == 0 {
			result = append(result, model.NewFinding(model.Candidate, "K8S.PDB.NO_DISRUPTIONS_ALLOWED", "ワークロード（Deploymentなど）", resource, "NoDisruptionsAllowed", "disruptions", fmt.Sprintf("PDB %s では、現在Podを安全に退避（Eviction）できる余裕がありません。Nodeのdrain処理が待機する可能性があります", shortRef(pdb.Namespace, pdb.Name)), 50,
				model.Evidence{Kind: "status", Key: "disruptionsAllowed", Value: "0"}))
		}
	}
	return result
}

// pdbProtectsNothing reports a PodDisruptionBudget whose selector matches no
// Pod. Nothing in the status says so — every counter simply reads zero — so a
// budget that guards nothing looks exactly like one that has nothing to do. The
// consequence only shows up during a drain, when the protection an operator
// believed was in place turns out never to have applied to anything.
func pdbProtectsNothing(pdb *policyv1.PodDisruptionBudget, podIndex podsByNamespace, snapshot *kube.Snapshot, resource string) (model.Finding, bool) {
	if !snapshot.AvailableOrUntracked("pods") || pdb.Status.ExpectedPods > 0 {
		return model.Finding{}, false
	}
	selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
	if err != nil {
		return model.NewFinding(
			model.Unavailable, "K8S.PDB.SELECTOR_UNAVAILABLE", "ワークロード（Deploymentなど）", resource, "SelectorParseFailed", "selector",
			fmt.Sprintf("PDB %s のPod選択条件（selector）を解析できません", shortRef(pdb.Namespace, pdb.Name)), 100,
			model.Evidence{Kind: "decision", Key: "selector", Value: err.Error()},
		), true
	}
	// An empty selector matches every Pod in the namespace, which is a different
	// configuration entirely and not this rule's subject.
	if pdb.Spec.Selector == nil || selector.Empty() {
		return model.Finding{}, false
	}
	candidates := podIndex[pdb.Namespace]
	for _, pod := range candidates {
		if selector.Matches(labels.Set(pod.Labels)) {
			return model.Finding{}, false
		}
	}
	// With no Pods collected at all there is no evidence either way: the
	// namespace may simply be empty at this moment.
	if len(candidates) == 0 {
		return model.Finding{}, false
	}
	return model.NewFinding(
		model.Warning, "K8S.PDB.SELECTOR_NO_MATCH", "ワークロード（Deploymentなど）", resource, "SelectorNoMatch", "selector-no-match",
		fmt.Sprintf("PDB %s のPod選択条件（selector）に一致するPodがありません。このPDBは何も保護していないため、Nodeのdrain時に想定した退避制限が働きません。ラベルの誤りか、対象ワークロードが0台に縮小されている可能性があります", shortRef(pdb.Namespace, pdb.Name)), 70,
		model.Evidence{Kind: "pdb", Key: "spec.selector", Value: "PDBのselector: " + metav1.FormatLabelSelector(pdb.Spec.Selector)},
		model.Evidence{Kind: "pod", Key: "namespacePods", Value: fmt.Sprintf("同じnamespaceのPod: %d件（うち一致 0件）", len(candidates))},
		model.Evidence{Kind: "status", Key: "expectedPods", Value: "status.expectedPods: 0"},
	), true
}

type APIServiceRule struct{}

func (APIServiceRule) Metadata() Metadata {
	return Metadata{ID: "apiservices", Section: "APIService", Description: "集約API（APIService）の利用可否", Required: []string{"apiservices"}, Permissions: cluster("apiregistration.k8s.io", "apiservices"), Modes: []string{"all", "triage"}}
}

func (APIServiceRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.APIServices {
		item := &snapshot.APIServices[i]
		conditions, _, _ := unstructured.NestedSlice(item.Object, "status", "conditions")
		for _, raw := range conditions {
			condition, ok := raw.(map[string]any)
			if !ok || objectStringField(condition, "type") != "Available" || objectStringField(condition, "status") == "True" {
				continue
			}
			reason, message := objectStringField(condition, "reason"), objectStringField(condition, "message")
			result = append(result, model.NewFinding(model.Warning, "K8S.APISERVICE.UNAVAILABLE", "APIService", ref("APIService", "", item.GetName()), reason, "available", conditionStateMessage("APIService", item.GetName(), "Available", "False", reason), 90, model.Evidence{Kind: "condition", Key: "Available", Value: message}))
		}
	}
	return result
}

type ControlPlaneRule struct{}

func (ControlPlaneRule) Metadata() Metadata {
	// A failed health endpoint normally returns a non-2xx status. Keep each
	// endpoint optional so the response body can still be evaluated while the
	// acquisition failure remains visible in Coverage.
	return Metadata{ID: "control-plane", Section: "コントロールプレーン", Description: "API Serverのreadyz・livezヘルスチェック", Optional: []string{"readyz", "livez"}, Modes: []string{"all", "triage"}}
}

type APIDeprecationRule struct{}

func (APIDeprecationRule) Metadata() Metadata {
	return Metadata{ID: "api-deprecation-warnings", Section: "API", Description: "Kubernetes APIの非推奨警告", Modes: []string{"all", "triage"}}
}

func (APIDeprecationRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for _, warning := range snapshot.APIWarnings {
		result = append(result, model.NewFinding(model.Candidate, "K8S.API.DEPRECATION_WARNING", "API", "API/warning", "DeprecationWarning", warning, "Kubernetes APIから非推奨に関する警告が返されました。内容: "+warning, 45))
	}
	return result
}

func (ControlPlaneRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	checks := []struct{ name, body, code string }{{"readyz", snapshot.Readyz, "K8S.CONTROL_PLANE.READYZ_FAILED"}, {"livez", snapshot.Livez, "K8S.CONTROL_PLANE.LIVEZ_FAILED"}}
	for _, check := range checks {
		reason := "ReadyzFailed"
		if check.name == "livez" {
			reason = "LivezFailed"
		}
		foundFailureLine := false
		for _, line := range strings.Split(check.body, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[-]") {
				foundFailureLine = true
				result = append(result, model.NewFinding(model.Issue, check.code, "コントロールプレーン", "ControlPlane/"+check.name, reason, trimmed, fmt.Sprintf("API Serverの %s ヘルスチェックで失敗が報告されました。内容: %s", check.name, trimmed), 98))
			}
		}
		status := snapshot.Status(check.name)
		if !foundFailureLine && status.HTTPCode >= 500 && status.HTTPCode <= 599 {
			result = append(result, model.NewFinding(
				model.Issue, check.code, "コントロールプレーン", "ControlPlane/"+check.name, reason, fmt.Sprintf("http-%d", status.HTTPCode),
				fmt.Sprintf("API Serverの %s ヘルスチェックがHTTP %dを返しました", check.name, status.HTTPCode), 98,
				model.Evidence{Kind: "http", Key: "statusCode", Value: fmt.Sprint(status.HTTPCode)},
			))
		}
	}
	return result
}

// Keep the typed core import anchored; ResourceQuota maps use ResourceName but
// callers should not convert it through free-form strings for arithmetic.
var _ corev1.ResourceName
