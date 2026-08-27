package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type WorkloadRule struct{}

func (WorkloadRule) Metadata() Metadata {
	return Metadata{
		ID: "workloads", Section: "ワークロード（Deploymentなど）", Description: "ワークロードのレプリカ数とロールアウト状態",
		Required:    []string{"deployments", "statefulsets", "daemonsets", "replicasets"},
		Optional:    []string{"pods"},
		Permissions: append(namespaced("apps", "deployments,statefulsets,daemonsets,replicasets"), namespaced("", "pods")...),
		Modes:       []string{"all", "triage"},
	}
}

func (WorkloadRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.Deployments {
		deployment := &snapshot.Deployments[i]
		if !statusGenerationCurrent(deployment.Generation, deployment.Status.ObservedGeneration) {
			continue
		}
		resource := ref("Deployment", deployment.Namespace, deployment.Name)
		short := shortRef(deployment.Namespace, deployment.Name)
		normalRollout := false
		hardRolloutFailure := false
		for _, c := range deployment.Status.Conditions {
			if c.Type == appsv1.DeploymentProgressing && c.Status == "False" && c.Reason == "ProgressDeadlineExceeded" {
				hardRolloutFailure = true
				result = append(result, model.NewFinding(
					model.Issue, "K8S.WORKLOAD.PROGRESS_DEADLINE_EXCEEDED", "ワークロード（Deploymentなど）", resource,
					c.Reason, "progress-deadline", fmt.Sprintf("Deployment %s のロールアウトは、progressDeadlineSecondsを超えても完了していません", short), 100,
					model.Evidence{Kind: "condition", Key: string(c.Type), Value: c.Message},
				))
			}
			if c.Type == appsv1.DeploymentReplicaFailure && c.Status == "True" {
				hardRolloutFailure = true
				result = append(result, model.NewFinding(
					model.Issue, "K8S.WORKLOAD.REPLICA_FAILURE", "ワークロード（Deploymentなど）", resource,
					c.Reason, "replica-failure", fmt.Sprintf("Deployment %s はレプリカ（Pod）を作成できません%s", short, reasonSuffix(c.Reason)), 100,
					model.Evidence{Kind: "condition", Key: string(c.Type), Value: c.Message},
				))
			}
			if c.Type == appsv1.DeploymentProgressing && c.Status == "True" && (c.Reason == "NewReplicaSetCreated" || c.Reason == "FoundNewReplicaSet" || c.Reason == "ReplicaSetUpdated") {
				normalRollout = true
			}
		}
		desired := int32Value(deployment.Spec.Replicas, 1)
		if desired > 0 && deployment.Status.ReadyReplicas < desired && (!normalRollout || hardRolloutFailure) {
			result = append(result, model.NewFinding(
				model.Warning, "K8S.WORKLOAD.REPLICAS_UNAVAILABLE", "ワークロード（Deploymentなど）", resource,
				"ReadyReplicasUnavailable", "ready-replicas", readyCountMessage("Deployment", short, deployment.Status.ReadyReplicas, desired), 75,
				model.Evidence{Kind: "status", Key: "readyReplicas", Value: fmt.Sprintf("%d/%d", deployment.Status.ReadyReplicas, desired)},
			))
		}
	}
	for i := range snapshot.ReplicaSets {
		rs := &snapshot.ReplicaSets[i]
		if !statusGenerationCurrent(rs.Generation, rs.Status.ObservedGeneration) {
			continue
		}
		for _, c := range rs.Status.Conditions {
			if c.Type == appsv1.ReplicaSetReplicaFailure && c.Status == "True" {
				result = append(result, model.NewFinding(
					model.Issue, "K8S.WORKLOAD.REPLICA_FAILURE", "ワークロード（Deploymentなど）", ref("ReplicaSet", rs.Namespace, rs.Name),
					c.Reason, "replica-failure", fmt.Sprintf("ReplicaSet %s はレプリカ（Pod）を作成できません%s", shortRef(rs.Namespace, rs.Name), reasonSuffix(c.Reason)), 100,
					model.Evidence{Kind: "condition", Key: string(c.Type), Value: c.Message},
				))
			}
		}
	}
	for i := range snapshot.StatefulSets {
		item := &snapshot.StatefulSets[i]
		if !statusGenerationCurrent(item.Generation, item.Status.ObservedGeneration) {
			continue
		}
		desired := int32Value(item.Spec.Replicas, 1)
		if desired > 0 && item.Status.ReadyReplicas < desired {
			result = append(result, model.NewFinding(model.Warning, "K8S.WORKLOAD.REPLICAS_UNAVAILABLE", "ワークロード（Deploymentなど）", ref("StatefulSet", item.Namespace, item.Name), "ReadyReplicasUnavailable", "ready-replicas", readyCountMessage("StatefulSet", shortRef(item.Namespace, item.Name), item.Status.ReadyReplicas, desired), 75))
		}
	}
	for i := range snapshot.DaemonSets {
		item := &snapshot.DaemonSets[i]
		if !statusGenerationCurrent(item.Generation, item.Status.ObservedGeneration) {
			continue
		}
		if item.Status.DesiredNumberScheduled > 0 && item.Status.NumberReady < item.Status.DesiredNumberScheduled {
			result = append(result, model.NewFinding(model.Warning, "K8S.WORKLOAD.REPLICAS_UNAVAILABLE", "ワークロード（Deploymentなど）", ref("DaemonSet", item.Namespace, item.Name), "ReadyReplicasUnavailable", "ready-replicas", readyCountMessage("DaemonSet", shortRef(item.Namespace, item.Name), item.Status.NumberReady, item.Status.DesiredNumberScheduled), 75))
		}
	}
	return append(result, overlappingSelectorFindings(snapshot)...)
}

// workloadSelector names one top-level controller and the Pods its selector
// claims. ReplicaSets are deliberately excluded: a Deployment always overlaps
// its own ReplicaSet, and reporting that would bury the case that matters.
type workloadSelector struct {
	kind      string
	namespace string
	name      string
	selector  labels.Selector
}

// overlappingSelectorFindings reports Pods claimed by more than one workload.
//
// Kubernetes does not stop two Deployments from selecting the same Pods, and
// nothing in either object's status records the collision. Their ReplicaSets
// then fight over the same Pods: each counts the other's as its own, scales
// against them, and deletes them to reach its replica count. The symptom is
// Pods appearing and disappearing with both Deployments looking healthy, and
// the cause is invisible unless the two manifests are read side by side.
func overlappingSelectorFindings(snapshot *kube.Snapshot) []model.Finding {
	if !snapshot.AvailableOrUntracked("pods") {
		return nil
	}
	owners := []workloadSelector{}
	add := func(kind, namespace, name string, spec *metav1.LabelSelector) {
		selector, err := metav1.LabelSelectorAsSelector(spec)
		// An empty selector claims nothing here: Kubernetes requires a selector
		// on these kinds, so an empty one means the object is not usable rather
		// than that it owns the whole namespace.
		if err != nil || spec == nil || selector.Empty() {
			return
		}
		owners = append(owners, workloadSelector{kind, namespace, name, selector})
	}
	for i := range snapshot.Deployments {
		add("Deployment", snapshot.Deployments[i].Namespace, snapshot.Deployments[i].Name, snapshot.Deployments[i].Spec.Selector)
	}
	for i := range snapshot.StatefulSets {
		add("StatefulSet", snapshot.StatefulSets[i].Namespace, snapshot.StatefulSets[i].Name, snapshot.StatefulSets[i].Spec.Selector)
	}
	for i := range snapshot.DaemonSets {
		add("DaemonSet", snapshot.DaemonSets[i].Namespace, snapshot.DaemonSets[i].Name, snapshot.DaemonSets[i].Spec.Selector)
	}
	if len(owners) < 2 {
		return nil
	}
	// Report per colliding pair rather than per Pod: one mistake between two
	// controllers usually spans every Pod they share.
	pairs := map[string][]string{}
	pairOrder := []string{}
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		claimed := []workloadSelector{}
		for _, owner := range owners {
			if owner.namespace == pod.Namespace && owner.selector.Matches(labels.Set(pod.Labels)) {
				claimed = append(claimed, owner)
			}
		}
		if len(claimed) < 2 {
			continue
		}
		names := make([]string, 0, len(claimed))
		for _, owner := range claimed {
			names = append(names, owner.kind+" "+owner.name)
		}
		sort.Strings(names)
		key := pod.Namespace + "\x00" + strings.Join(names, " / ")
		if _, seen := pairs[key]; !seen {
			pairOrder = append(pairOrder, key)
		}
		pairs[key] = append(pairs[key], pod.Name)
	}
	result := []model.Finding{}
	for _, key := range pairOrder {
		namespace, owners, _ := strings.Cut(key, "\x00")
		claimedPods := pairs[key]
		sort.Strings(claimedPods)
		result = append(result, model.NewFinding(
			model.Warning, "K8S.WORKLOAD.SELECTOR_OVERLAP", "ワークロード（Deploymentなど）",
			ref("Pod", namespace, claimedPods[0]), "SelectorOverlap", namespace+"/"+owners,
			fmt.Sprintf("namespace %s の %s は、同じPodを対象にするPod選択条件（selector）を持っています。対象Pod: %s。それぞれのコントローラが同じPodを自分のものとして数え、レプリカ数を合わせるために削除し合うため、Podの増減が繰り返される場合があります",
				namespace, owners, summarizeStrings(claimedPods, 5)), 80,
			model.Evidence{Kind: "workload", Key: "selector", Value: "同じPodを対象にしているワークロード: " + owners},
			model.Evidence{Kind: "pod", Key: "claimed", Value: fmt.Sprintf("重複して対象になっているPod: %s（%d件）", summarizeStrings(claimedPods, 5), len(claimedPods))},
			model.Evidence{Kind: "decision", Key: "overlap", Value: "Kubernetesはselectorの重複を禁止しませんが、公式ドキュメントは重複するラベルのワークロードを作らないよう求めています"},
		))
	}
	return result
}
