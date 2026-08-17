package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	resourcehelper "k8s.io/component-helpers/resource"
	schedulinghelper "k8s.io/component-helpers/scheduling/corev1"
	ephemeralhelper "k8s.io/component-helpers/storage/ephemeral"
	volumehelper "k8s.io/component-helpers/storage/volume"
)

// SchedulingRule performs a conservative, explainable subset of kube-scheduler
// filtering. Resource calculation and taint/node-affinity semantics are
// delegated to Kubernetes' own component-helpers to prevent version drift.
type SchedulingRule struct{}

func (SchedulingRule) Metadata() Metadata {
	permissions := namespaced("", "pods,persistentvolumeclaims,events")
	permissions = append(permissions, cluster("", "nodes")...)
	permissions = append(permissions, cluster("", "persistentvolumes")...)
	permissions = append(permissions, cluster("storage.k8s.io", "storageclasses")...)
	return Metadata{
		ID: "pending-scheduling", Section: "Scheduling", Description: "Pending PodをNodeへ配置できるかの判定",
		Required:    []string{"pods", "nodes"},
		Optional:    []string{"all_pods", "pvcs", "pvs", "storageclasses", "events"},
		Permissions: permissions, Modes: []string{"all", "triage", "select"},
	}
}

type nodeAssessment struct {
	Node       string
	Reasons    []string
	Unknowns   []string
	Categories map[schedulingCategory]struct{}
}

type schedulingCategory string

const (
	categoryNodeAffinity schedulingCategory = "node-affinity"
	categoryTaint        schedulingCategory = "taint"
	categoryPVC          schedulingCategory = "pvc"
	categoryResources    schedulingCategory = "resources"
)

func (a *nodeAssessment) reject(category schedulingCategory, reason string) {
	if a.Categories == nil {
		a.Categories = map[schedulingCategory]struct{}{}
	}
	a.Categories[category] = struct{}{}
	a.Reasons = append(a.Reasons, reason)
}

func (SchedulingRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	assigned := assignedRequests(snapshot.AllPods)
	allPodsKnown := snapshot.AvailableOrUntracked("all_pods")
	if !allPodsKnown || len(snapshot.AllPods) == 0 {
		assigned = assignedRequests(snapshot.Pods)
	}
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		if pod.Status.Phase != corev1.PodPending || pod.Spec.NodeName != "" {
			continue
		}
		resourceRef := ref("Pod", pod.Namespace, pod.Name)
		short := shortRef(pod.Namespace, pod.Name)
		events := podSchedulingEvents(pod, snapshot.Events)
		directEvidence, evidenceText := schedulingEvidence(pod, events)
		age := elapsedSince(snapshot, pod.CreationTimestamp.Time)

		if pod.Status.NominatedNodeName != "" {
			if age < 5*time.Minute {
				continue
			}
			code, reason, confidence := "K8S.SCHEDULING.NOMINATED_NODE_PENDING", "NominatedNodePending", 70
			message := fmt.Sprintf("Pod %s では、候補として指名されたNode %q へのバインド処理が5分以上完了していません", short, pod.Status.NominatedNodeName)
			if confirmsPreemption(events) {
				code, reason, confidence = "K8S.SCHEDULING.PREEMPTION_PENDING", "PreemptionPending", 90
				message = fmt.Sprintf("Pod %s はPreemption処理中ですが、候補Node %q への配置が5分以上完了していません", short, pod.Status.NominatedNodeName)
			}
			result = append(result, model.NewFinding(model.Warning, code, "Scheduling", resourceRef, reason, "nominated-node", message, confidence, model.Evidence{Kind: "pod", Key: "nominatedNodeName", Value: pod.Status.NominatedNodeName}))
			continue
		}

		if len(pod.Spec.SchedulingGates) > 0 {
			result = append(result, model.NewFinding(model.Candidate, "K8S.SCHEDULING.GATED", "Scheduling", resourceRef, "SchedulingGated", "scheduling-gates", fmt.Sprintf("Pod %s は、%d件の schedulingGate が解除されるのを待っています", short, len(pod.Spec.SchedulingGates)), 50))
			continue
		}
		if pod.Spec.SchedulerName != "" && pod.Spec.SchedulerName != corev1.DefaultSchedulerName {
			result = append(result, model.NewFinding(model.Candidate, "K8S.SCHEDULING.CUSTOM_SCHEDULER", "Scheduling", resourceRef, "CustomScheduler", pod.Spec.SchedulerName, fmt.Sprintf("Pod %s はカスタムScheduler %q を使用しています。このツールでは、そのSchedulerによる配置判定を完全には再現できません", short, pod.Spec.SchedulerName), 40))
			continue
		}

		requests := resourcehelper.PodRequests(pod, resourcehelper.PodResourcesOptions{UseStatusResources: true})
		pvcDataKnown := snapshot.AvailableOrUntracked("pvcs") && snapshot.AvailableOrUntracked("storageclasses")
		assessments := make([]nodeAssessment, 0, len(snapshot.Nodes))
		feasible := 0
		feasibleWithUnknowns := 0
		for nodeIndex := range snapshot.Nodes {
			node := &snapshot.Nodes[nodeIndex]
			pvcReasons, pvcUnknowns := []string{}, []string{}
			if pvcDataKnown {
				pvcReasons, pvcUnknowns = pvcNodeSchedulingConstraints(pod, node, snapshot)
			}
			assessment := assessNodeWithPVC(pod, node, requests, assigned[node.Name], pvcReasons)
			assessment.Unknowns = append(assessment.Unknowns, pvcUnknowns...)
			if len(assessment.Reasons) == 0 {
				feasible++
				if len(assessment.Unknowns) > 0 {
					feasibleWithUnknowns++
				}
			}
			assessments = append(assessments, assessment)
		}
		unknowns := unsupportedSchedulingConstraints(pod)
		if !allPodsKnown {
			unknowns = append(unknowns, "すべてのNamespaceのPodを取得できなかったため、Nodeの使用量は取得できた範囲で評価しています")
		}
		if podUsesPVC(pod) && !pvcDataKnown {
			unknowns = append(unknowns, "PVCまたはStorageClassを取得できなかったため、ボリューム制約を評価していません")
		}
		for _, assessment := range assessments {
			unknowns = append(unknowns, assessment.Unknowns...)
		}
		complete := len(unknowns) == 0 && len(snapshot.Nodes) > 0
		severity, confidence := model.Warning, 75
		if feasible == 0 && complete && directEvidence && age >= 5*time.Minute {
			severity, confidence = model.Issue, 95
		}
		code, reason := dominantSchedulingCode(assessments)
		if feasible > 0 {
			code, reason = "K8S.SCHEDULING.FAILED_SCHEDULING_REPORTED", "FailedSchedulingReported"
		}
		message := fmt.Sprintf("Pod %s を配置できるNodeは、%d台中 %d台です", short, len(snapshot.Nodes), feasible)
		if !complete {
			message += "。未評価の制約があるため、この結果だけでは配置可否を確定できません"
		}
		if feasibleWithUnknowns > 0 {
			message += fmt.Sprintf("。配置可能と判定したNodeのうち、%d台には未評価の項目があります", feasibleWithUnknowns)
		}
		evidenceValues := []model.Evidence{
			{Kind: "scheduling", Key: "podAge", Value: age.Round(time.Second).String()},
			{Kind: "scheduling", Key: "feasibleNodes", Value: fmt.Sprintf("%d/%d", feasible, len(snapshot.Nodes))},
		}
		if evidenceText != "" {
			evidenceValues = append(evidenceValues, model.Evidence{Kind: "event", Key: "directEvidence", Value: evidenceText})
		}
		for _, assessment := range assessments {
			if len(assessment.Reasons) > 0 {
				evidenceValues = append(evidenceValues, model.Evidence{Kind: "node", Key: assessment.Node, Value: strings.Join(assessment.Reasons, "; ")})
			}
		}
		for _, unknown := range uniqueSorted(unknowns) {
			evidenceValues = append(evidenceValues, model.Evidence{Kind: "unknown", Key: "constraint", Value: unknown})
		}
		result = append(result, model.NewFinding(severity, code, "Scheduling", resourceRef, reason, "pending-scheduling", message, confidence, evidenceValues...))
	}
	return result
}

func assignedRequests(pods []corev1.Pod) map[string]corev1.ResourceList {
	result := map[string]corev1.ResourceList{}
	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName == "" || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if result[pod.Spec.NodeName] == nil {
			result[pod.Spec.NodeName] = corev1.ResourceList{}
		}
		addResourceList(result[pod.Spec.NodeName], resourcehelper.PodRequests(pod, resourcehelper.PodResourcesOptions{UseStatusResources: true}))
		podsQuantity := result[pod.Spec.NodeName][corev1.ResourcePods]
		podsQuantity.Add(*resource.NewQuantity(1, resource.DecimalSI))
		result[pod.Spec.NodeName][corev1.ResourcePods] = podsQuantity
	}
	return result
}

func addResourceList(target, values corev1.ResourceList) {
	for name, quantity := range values {
		current := target[name]
		current.Add(quantity)
		target[name] = current
	}
}

func assessNodeWithPVC(pod *corev1.Pod, node *corev1.Node, requests, used corev1.ResourceList, pvcReasons []string) nodeAssessment {
	assessment := nodeAssessment{Node: node.Name, Categories: map[schedulingCategory]struct{}{}}
	for key, expected := range pod.Spec.NodeSelector {
		if node.Labels[key] != expected {
			assessment.reject(categoryNodeAffinity, fmt.Sprintf("Nodeのラベルが、nodeSelector で要求された %s=%s と一致しません", key, expected))
		}
	}
	if affinity := pod.Spec.Affinity; affinity != nil && affinity.NodeAffinity != nil && affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
		matched, err := schedulinghelper.MatchNodeSelectorTerms(node, affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution)
		if err != nil {
			assessment.Unknowns = append(assessment.Unknowns, "必須の nodeAffinity を解析できません。原因: "+err.Error())
		} else if !matched {
			assessment.reject(categoryNodeAffinity, "必須の nodeAffinity 条件と一致しません")
		}
	}

	taints := append([]corev1.Taint{}, node.Spec.Taints...)
	if node.Spec.Unschedulable && !hasTaint(taints, corev1.TaintNodeUnschedulable) {
		taints = append(taints, corev1.Taint{Key: corev1.TaintNodeUnschedulable, Effect: corev1.TaintEffectNoSchedule})
	}
	// Ready=False/Unknown is valuable evidence, but the scheduler-facing hard
	// constraint is the node.kubernetes.io/not-ready or unreachable taint. Do
	// not synthesize one here: during the short condition/taint propagation gap,
	// doing so would reject a Pod that the scheduler itself may still evaluate.
	if taint, untolerated := schedulinghelper.FindMatchingUntoleratedTaint(taints, pod.Spec.Tolerations, func(taint *corev1.Taint) bool {
		return taint.Effect == corev1.TaintEffectNoSchedule || taint.Effect == corev1.TaintEffectNoExecute
	}); untolerated {
		assessment.reject(categoryTaint, fmt.Sprintf("Podには、taint %s:%s を許容する toleration が設定されていません", taint.Key, taint.Effect))
	}

	for name, requested := range requests {
		if requested.Sign() <= 0 {
			continue
		}
		capacity, exists := node.Status.Allocatable[name]
		if !exists {
			capacity = *resource.NewQuantity(0, requested.Format) // absent extended resources are zero
		}
		available := capacity.DeepCopy()
		if assigned, ok := used[name]; ok {
			available.Sub(assigned)
		}
		if available.Sign() < 0 {
			available = *resource.NewQuantity(0, requested.Format)
		}
		if requested.Cmp(available) > 0 {
			assessment.reject(categoryResources, fmt.Sprintf("リソース %s の要求量は %s ですが、空き容量は %s です", name, requested.String(), available.String()))
		}
	}

	if pod.Spec.NodeName == "" {
		usedPods := used[corev1.ResourcePods]
		if capacity, exists := node.Status.Allocatable[corev1.ResourcePods]; exists {
			remaining := capacity.DeepCopy()
			remaining.Sub(usedPods)
			one := *resource.NewQuantity(1, resource.DecimalSI)
			if one.Cmp(remaining) > 0 {
				assessment.reject(categoryResources, "Nodeに配置できるPod数の上限に達しています")
			}
		} else {
			assessment.Unknowns = append(assessment.Unknowns, "Nodeから allocatable.pods が報告されていないため、配置可能なPod数の上限を評価できません")
		}
	}
	for _, reason := range pvcReasons {
		assessment.reject(categoryPVC, reason)
	}
	return assessment
}

func podUsesPVC(pod *corev1.Pod) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil || volume.Ephemeral != nil {
			return true
		}
	}
	return false
}

type podPVCReference struct {
	claimName string
	volume    string
	ephemeral bool
}

func podPVCReferences(pod *corev1.Pod) []podPVCReference {
	result := []podPVCReference{}
	for i := range pod.Spec.Volumes {
		volume := &pod.Spec.Volumes[i]
		switch {
		case volume.PersistentVolumeClaim != nil:
			result = append(result, podPVCReference{claimName: volume.PersistentVolumeClaim.ClaimName, volume: volume.Name})
		case volume.Ephemeral != nil:
			result = append(result, podPVCReference{claimName: ephemeralhelper.VolumeClaimName(pod, volume), volume: volume.Name, ephemeral: true})
		}
	}
	return result
}

func hasTaint(taints []corev1.Taint, key string) bool {
	for _, taint := range taints {
		if taint.Key == key && (taint.Effect == corev1.TaintEffectNoSchedule || taint.Effect == corev1.TaintEffectNoExecute) {
			return true
		}
	}
	return false
}

func pvcNodeSchedulingConstraints(pod *corev1.Pod, node *corev1.Node, snapshot *kube.Snapshot) ([]string, []string) {
	result := []string{}
	unknowns := []string{}
	pvsTrackedStatus, pvsTracked := snapshot.Statuses["pvs"]
	pvsKnown := pvsTracked && pvsTrackedStatus.Available || !pvsTracked && len(snapshot.PersistentVolumes) > 0
	for _, reference := range podPVCReferences(pod) {
		name := reference.claimName
		pvc, _ := snapshot.PersistentVolumeClaim(pod.Namespace, name)
		if pvc == nil {
			if reference.ephemeral {
				result = append(result, fmt.Sprintf("Generic Ephemeral Volume %q に必要なPVC %q が存在しません", reference.volume, name))
			} else {
				result = append(result, fmt.Sprintf("参照しているPVC %q が存在しません", name))
			}
			continue
		}
		if reference.ephemeral {
			if err := ephemeralhelper.VolumeIsForPod(pod, pvc); err != nil {
				result = append(result, fmt.Sprintf("Generic Ephemeral Volume %q のPVC %q は、このPodによって所有されていません", reference.volume, name))
				continue
			}
		}
		if node != nil {
			if selectedNode := pvc.Annotations[volumehelper.AnnSelectedNode]; selectedNode != "" && selectedNode != node.Name {
				result = append(result, fmt.Sprintf("PVC %q はNode %q 向けに選択済みのため、現在評価中のNodeとは一致しません", name, selectedNode))
				continue
			}
		}
		if pvc.DeletionTimestamp != nil {
			result = append(result, fmt.Sprintf("PVC %q は削除処理中です", name))
			continue
		}
		if pvc.Status.Phase == corev1.ClaimBound {
			if pvc.Spec.VolumeName == "" {
				unknowns = append(unknowns, fmt.Sprintf("Bound 状態のPVC %q で spec.volumeName が空のため、PVの制約を確認できません", name))
				continue
			}
			if !pvsKnown {
				unknowns = append(unknowns, fmt.Sprintf("PVを取得できなかったため、PVC %q の nodeAffinity は評価していません", name))
				continue
			}
			persistentVolume, _ := snapshot.PersistentVolume(pvc.Spec.VolumeName)
			if persistentVolume == nil {
				result = append(result, fmt.Sprintf("PVC %q が参照するPV %q は存在しません", name, pvc.Spec.VolumeName))
				continue
			}
			if node != nil {
				if err := volumehelper.CheckNodeAffinity(persistentVolume, node.Labels); err != nil {
					result = append(result, fmt.Sprintf("PV %q の nodeAffinity と、このNodeのラベルが一致しません", persistentVolume.Name))
				}
			}
			continue
		}
		className := ""
		if pvc.Spec.StorageClassName != nil {
			className = *pvc.Spec.StorageClassName
		}
		class, _ := snapshot.StorageClass(className)
		waitForConsumer := class != nil && class.VolumeBindingMode != nil && *class.VolumeBindingMode == storagev1.VolumeBindingWaitForFirstConsumer
		if pvc.Status.Phase == corev1.ClaimPending && waitForConsumer {
			if node != nil && !matchesAllowedTopologies(class.AllowedTopologies, node.Labels) {
				result = append(result, fmt.Sprintf("StorageClass %q の allowedTopologies には、このNodeが含まれていません", className))
				continue
			}
			unknowns = append(unknowns, fmt.Sprintf("PVC %q の動的プロビジョニングでは、容量の確保とPVの選択を静的に評価できません", name))
			continue
		}
		result = append(result, fmt.Sprintf("PVC %q はバインドされていません（現在のphase: %s）", name, pvc.Status.Phase))
	}
	return uniqueSorted(result), uniqueSorted(unknowns)
}

func matchesAllowedTopologies(terms []corev1.TopologySelectorTerm, labels map[string]string) bool {
	if len(terms) == 0 {
		return true
	}
	for _, term := range terms {
		matched := true
		for _, expression := range term.MatchLabelExpressions {
			actual, exists := labels[expression.Key]
			if !exists || !contains(expression.Values, actual) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func unsupportedSchedulingConstraints(pod *corev1.Pod) []string {
	result := []string{}
	if pod.Spec.Affinity != nil {
		if pod.Spec.Affinity.PodAffinity != nil && len(pod.Spec.Affinity.PodAffinity.RequiredDuringSchedulingIgnoredDuringExecution) > 0 {
			result = append(result, "必須の podAffinity は静的に評価していません")
		}
		if pod.Spec.Affinity.PodAntiAffinity != nil && len(pod.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) > 0 {
			result = append(result, "必須の podAntiAffinity は静的に評価していません")
		}
	}
	if len(pod.Spec.TopologySpreadConstraints) > 0 {
		result = append(result, "topologySpreadConstraints は静的に評価していません")
	}
	for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		for _, port := range container.Ports {
			if port.HostPort > 0 {
				result = append(result, "hostPort の競合は静的に評価していません")
				break
			}
		}
	}
	if len(pod.Spec.ResourceClaims) > 0 {
		result = append(result, "DRAの resourceClaims は静的に評価していません")
	}
	return uniqueSorted(result)
}

func podSchedulingEvents(pod *corev1.Pod, events []corev1.Event) []corev1.Event {
	result := []corev1.Event{}
	for i := range events {
		event := events[i]
		if event.InvolvedObject.Kind != "Pod" || event.InvolvedObject.Namespace != pod.Namespace || event.InvolvedObject.Name != pod.Name {
			continue
		}
		if event.InvolvedObject.UID != "" && pod.UID != "" && event.InvolvedObject.UID != pod.UID {
			continue
		}
		if event.Reason == "FailedScheduling" || strings.Contains(strings.ToLower(event.Message), "preempt") || strings.Contains(strings.ToLower(event.Message), "permit") {
			result = append(result, event)
		}
	}
	sort.Slice(result, func(i, j int) bool { return eventTime(&result[i]).After(eventTime(&result[j])) })
	return result
}

func schedulingEvidence(pod *corev1.Pod, events []corev1.Event) (bool, string) {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable {
			return true, strings.TrimSpace(c.Message)
		}
	}
	for _, event := range events {
		if event.Reason == "FailedScheduling" {
			return true, strings.TrimSpace(event.Message)
		}
	}
	return false, ""
}

func confirmsPreemption(events []corev1.Event) bool {
	negative := []string{"preemption is not helpful", "no preemption victims", "not eligible", "preemption not helpful"}
	for _, event := range events {
		text := strings.ToLower(event.Reason + " " + event.Message)
		if !strings.Contains(text, "preempt") {
			continue
		}
		denied := false
		for _, phrase := range negative {
			if strings.Contains(text, phrase) {
				denied = true
				break
			}
		}
		if !denied && (strings.Contains(text, "nominated") || strings.Contains(text, "victim") || strings.Contains(text, "preempted")) {
			return true
		}
	}
	return false
}

func dominantSchedulingCode(assessments []nodeAssessment) (string, string) {
	counts := map[schedulingCategory]int{}
	for _, assessment := range assessments {
		for category := range assessment.Categories {
			counts[category]++
		}
	}
	order := []struct {
		category     schedulingCategory
		code, reason string
	}{
		{categoryNodeAffinity, "K8S.SCHEDULING.NODE_AFFINITY_MISMATCH", "NodeAffinityMismatch"},
		{categoryTaint, "K8S.SCHEDULING.UNTOLERATED_TAINT", "UntoleratedTaint"},
		{categoryPVC, "K8S.SCHEDULING.PVC_CONSTRAINT", "PVCConstraint"},
		{categoryResources, "K8S.SCHEDULING.INSUFFICIENT_RESOURCES", "InsufficientResources"},
	}
	for _, candidate := range order {
		if len(assessments) > 0 && counts[candidate.category] == len(assessments) {
			return candidate.code, candidate.reason
		}
	}
	return "K8S.SCHEDULING.NO_AVAILABLE_NODE", "NoAvailableNode"
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
