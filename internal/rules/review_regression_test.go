package rules

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	resourcehelper "k8s.io/component-helpers/resource"
)

func pendingPod(name string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID("uid-" + name), CreationTimestamp: metav1.NewTime(time.Now().Add(-10 * time.Minute))},
		Spec:       corev1.PodSpec{SchedulerName: corev1.DefaultSchedulerName, Containers: []corev1.Container{{Name: "app"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodPending, Conditions: []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable, Message: "unschedulable"}}},
	}
}

func schedulableNode(name string) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("8Gi"), corev1.ResourcePods: resource.MustParse("110"),
		}},
	}
}

func schedulingFinding(t *testing.T, snapshot *kube.Snapshot, code string) model.Finding {
	t.Helper()
	for _, finding := range (SchedulingRule{}).Evaluate(context.Background(), snapshot, config.Defaults()) {
		if finding.Code == code {
			return finding
		}
	}
	t.Fatalf("所見 %s がありません", code)
	return model.Finding{}
}

func TestMissingExtendedAllocatableIsZeroCapacity(t *testing.T) {
	pod := pendingPod("gpu")
	pod.Spec.Containers[0].Resources.Requests = corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("1")}
	node := schedulableNode("node-a") // GPU key is intentionally absent.
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, Nodes: []corev1.Node{node}, Events: []corev1.Event{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns"}, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "ns", Name: pod.Name, UID: pod.UID}, Reason: "FailedScheduling", Message: "Insufficient nvidia.com/gpu",
	}}}
	finding := schedulingFinding(t, snapshot, "K8S.SCHEDULING.INSUFFICIENT_RESOURCES")
	if finding.Severity != model.Issue {
		t.Fatalf("severity=%s, want issue", finding.Severity)
	}
	if !evidenceContains(finding, "nvidia.com/gpu") {
		t.Fatalf("GPU不足の根拠がない: %#v", finding.Evidence)
	}
}

func TestPodLevelHugePagesOverridesContainerRequest(t *testing.T) {
	pod := pendingPod("hugepages")
	pod.Spec.Containers[0].Resources.Requests = corev1.ResourceList{corev1.ResourceName("hugepages-2Mi"): resource.MustParse("2Gi")}
	pod.Spec.Resources = &corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceName("hugepages-2Mi"): resource.MustParse("1Gi")}}
	requests := resourcehelper.PodRequests(&pod, resourcehelper.PodResourcesOptions{UseStatusResources: true})
	if got := requests[corev1.ResourceName("hugepages-2Mi")]; got.Cmp(resource.MustParse("1Gi")) != 0 {
		t.Fatalf("Pod-level HugePages=%s, want 1Gi", got.String())
	}
	node := schedulableNode("node-a")
	node.Status.Allocatable[corev1.ResourceName("hugepages-2Mi")] = resource.MustParse("1536Mi")
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, Nodes: []corev1.Node{node}}
	finding := schedulingFinding(t, snapshot, "K8S.SCHEDULING.FAILED_SCHEDULING_REPORTED")
	if !evidenceContains(finding, "1/1") {
		t.Fatalf("配置可能Nodeが1/1でない: %#v", finding.Evidence)
	}
}

func TestNodeStateAndCordonHonorTolerations(t *testing.T) {
	tests := []struct {
		name          string
		unschedulable bool
		taintKey      string
	}{
		{"not-ready", false, corev1.TaintNodeNotReady},
		{"cordon", true, corev1.TaintNodeUnschedulable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pod := pendingPod(test.name)
			pod.Spec.Tolerations = []corev1.Toleration{{Key: test.taintKey, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}
			node := schedulableNode("node-a")
			node.Spec.Unschedulable = test.unschedulable
			if test.taintKey == corev1.TaintNodeNotReady {
				node.Spec.Taints = []corev1.Taint{{Key: test.taintKey, Effect: corev1.TaintEffectNoSchedule}}
				node.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}
			}
			assessment := assessNodeForTest(&pod, &node, resourcehelper.PodRequests(&pod, resourcehelper.PodResourcesOptions{}), nil, &kube.Snapshot{})
			for _, reason := range assessment.Reasons {
				if strings.Contains(reason, "taint") {
					t.Fatalf("tolerationがあるのに拒否: %s", reason)
				}
			}
		})
	}
}

func TestReadyFalseWithoutTaintIsNotHardFilter(t *testing.T) {
	pod := pendingPod("condition-gap")
	node := schedulableNode("node-a")
	node.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}
	assessment := assessNodeForTest(&pod, &node, nil, nil, &kube.Snapshot{})
	if len(assessment.Reasons) != 0 {
		t.Fatalf("Ready=Falseだけで配置不可にした: %v", assessment.Reasons)
	}
}

func assessNodeForTest(pod *corev1.Pod, node *corev1.Node, requests, used corev1.ResourceList, snapshot *kube.Snapshot) nodeAssessment {
	pvcReasons, _ := pvcNodeSchedulingConstraints(pod, node, snapshot)
	return assessNodeWithPVC(pod, node, requests, used, pvcReasons)
}

func TestNodeHeartbeatUsesLeaseInsteadOfConditionTimestamp(t *testing.T) {
	node := schedulableNode("node-a")
	node.Status.Conditions = []corev1.NodeCondition{{
		Type: corev1.NodeReady, Status: corev1.ConditionTrue,
		LastHeartbeatTime: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
	}}
	fresh := metav1.NewMicroTime(time.Now().Add(-5 * time.Second))
	snapshot := &kube.Snapshot{
		Nodes: []corev1.Node{node},
		NodeLeases: []coordinationv1.Lease{{
			ObjectMeta: metav1.ObjectMeta{Name: node.Name, Namespace: corev1.NamespaceNodeLease},
			Spec:       coordinationv1.LeaseSpec{RenewTime: &fresh},
		}},
	}
	if findings := (NodeHeartbeatRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); len(findings) != 0 {
		t.Fatalf("freshなLeaseを古いNode condition時刻で誤検知した: %#v", findings)
	}
	stale := metav1.NewMicroTime(time.Now().Add(-4 * time.Minute))
	snapshot.NodeLeases[0].Spec.RenewTime = &stale
	findings := (NodeHeartbeatRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.NODE.HEARTBEAT_STALE", "Node/node-a") {
		t.Fatalf("staleなLeaseを検出できない: %#v", findings)
	}
}

func TestNodeHeartbeatUsesAPIServerTimeInsteadOfLocalClock(t *testing.T) {
	serverTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	renewed := metav1.NewMicroTime(serverTime.Add(-30 * time.Second))
	snapshot := &kube.Snapshot{ServerTime: serverTime, Nodes: []corev1.Node{schedulableNode("node-a")}, NodeLeases: []coordinationv1.Lease{{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Spec: coordinationv1.LeaseSpec{RenewTime: &renewed}}}}
	if findings := (NodeHeartbeatRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); len(findings) != 0 {
		t.Fatalf("ローカル時計との差でfresh Leaseを誤検知した: %#v", findings)
	}
}

func TestNewNodeGetsHeartbeatGracePeriodBeforeMissingLeaseWarning(t *testing.T) {
	serverTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	node := schedulableNode("node-a")
	node.CreationTimestamp = metav1.NewTime(serverTime.Add(-30 * time.Second))
	snapshot := &kube.Snapshot{ServerTime: serverTime, Nodes: []corev1.Node{node}}
	cfg := config.Defaults()
	cfg.NodeHeartbeatTimeout = 180
	if findings := (NodeHeartbeatRule{}).Evaluate(context.Background(), snapshot, cfg); len(findings) != 0 {
		t.Fatalf("作成直後のNodeをLease欠落として警告した: %#v", findings)
	}
	node.CreationTimestamp = metav1.NewTime(serverTime.Add(-181 * time.Second))
	snapshot.Nodes[0] = node
	findings := (NodeHeartbeatRule{}).Evaluate(context.Background(), snapshot, cfg)
	if !hasCodeAndResource(findings, "K8S.NODE.LEASE_MISSING", "Node/node-a") {
		t.Fatalf("猶予後のLease欠落を検出できない: %#v", findings)
	}
}

func TestWaitForFirstConsumerPendingPVCIsNotWarning(t *testing.T) {
	mode := storagev1.VolumeBindingWaitForFirstConsumer
	className := "delayed"
	snapshot := &kube.Snapshot{
		StorageClasses:         []storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: className}, VolumeBindingMode: &mode}},
		PersistentVolumeClaims: []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "ns"}, Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: &className}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}},
	}
	if findings := (StorageRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); len(findings) != 0 {
		t.Fatalf("WaitForFirstConsumerを異常扱いした: %#v", findings)
	}
}

func TestSchedulingEvaluatesBoundPVNodeAffinity(t *testing.T) {
	pod := pendingPod("pv-zone")
	pod.Spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}}}
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "ns"},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-data"},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
	}
	pv := corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-data"},
		Spec: corev1.PersistentVolumeSpec{NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{
			Key: "topology.kubernetes.io/zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"zone-a"},
		}}}}}}},
	}
	nodeA, nodeB := schedulableNode("node-a"), schedulableNode("node-b")
	nodeA.Labels = map[string]string{"topology.kubernetes.io/zone": "zone-a"}
	nodeB.Labels = map[string]string{"topology.kubernetes.io/zone": "zone-b"}
	snapshot := kube.NewSnapshot()
	snapshot.Pods, snapshot.Nodes = []corev1.Pod{pod}, []corev1.Node{nodeA, nodeB}
	snapshot.PersistentVolumeClaims, snapshot.PersistentVolumes = []corev1.PersistentVolumeClaim{pvc}, []corev1.PersistentVolume{pv}
	for _, key := range []string{"pvcs", "pvs", "storageclasses", "all_pods", "events"} {
		snapshot.Statuses[key] = kube.FetchStatus{Available: true}
	}
	finding := schedulingFinding(t, snapshot, "K8S.SCHEDULING.FAILED_SCHEDULING_REPORTED")
	if !strings.Contains(finding.Message, "2台中 1台") || !evidenceContains(finding, "PV \"pv-data\" の nodeAffinity") || !evidenceContains(finding, "一致しません") {
		t.Fatalf("Bound PV nodeAffinityをNode別に評価できない: %#v", finding)
	}
}

func TestSchedulingEvaluatesWaitForConsumerAllowedTopologiesConservatively(t *testing.T) {
	pod := pendingPod("wffc-zone")
	pod.Spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}}}
	className := "zonal"
	pvc := corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "ns"}, Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: &className}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}
	mode := storagev1.VolumeBindingWaitForFirstConsumer
	class := storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: className}, VolumeBindingMode: &mode, AllowedTopologies: []corev1.TopologySelectorTerm{{MatchLabelExpressions: []corev1.TopologySelectorLabelRequirement{{Key: "topology.kubernetes.io/zone", Values: []string{"zone-b"}}}}}}
	nodeA, nodeB := schedulableNode("node-a"), schedulableNode("node-b")
	nodeA.Labels = map[string]string{"topology.kubernetes.io/zone": "zone-a"}
	nodeB.Labels = map[string]string{"topology.kubernetes.io/zone": "zone-b"}
	snapshot := kube.NewSnapshot()
	snapshot.Pods, snapshot.Nodes = []corev1.Pod{pod}, []corev1.Node{nodeA, nodeB}
	snapshot.PersistentVolumeClaims, snapshot.StorageClasses = []corev1.PersistentVolumeClaim{pvc}, []storagev1.StorageClass{class}
	for _, key := range []string{"pvcs", "pvs", "storageclasses", "all_pods", "events"} {
		snapshot.Statuses[key] = kube.FetchStatus{Available: true}
	}
	finding := schedulingFinding(t, snapshot, "K8S.SCHEDULING.FAILED_SCHEDULING_REPORTED")
	if finding.Severity == model.Issue || !strings.Contains(finding.Message, "2台中 1台") || !evidenceContains(finding, "allowedTopologies") || !evidenceContains(finding, "動的プロビジョニング") {
		t.Fatalf("WFFC topologyまたはunknownを不正評価した: %#v", finding)
	}
}

func TestSchedulingHandlesGenericEphemeralPVCAndSelectedNode(t *testing.T) {
	pod := pendingPod("scratch")
	pod.Spec.Volumes = []corev1.Volume{{Name: "cache", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{}}}}}
	controller := true
	className := "delayed"
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "scratch-cache", Namespace: "ns",
			Annotations:     map[string]string{"volume.kubernetes.io/selected-node": "node-b"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID, Controller: &controller}},
		},
		Spec:   corev1.PersistentVolumeClaimSpec{StorageClassName: &className},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}
	mode := storagev1.VolumeBindingWaitForFirstConsumer
	snapshot := &kube.Snapshot{
		PersistentVolumeClaims: []corev1.PersistentVolumeClaim{pvc},
		StorageClasses:         []storagev1.StorageClass{{ObjectMeta: metav1.ObjectMeta{Name: className}, VolumeBindingMode: &mode}},
	}
	nodeA, nodeB := schedulableNode("node-a"), schedulableNode("node-b")
	reasonsA, _ := pvcNodeSchedulingConstraints(&pod, &nodeA, snapshot)
	if !containsText(reasonsA, "Node \"node-b\" 向けに選択済み") {
		t.Fatalf("generic ephemeral PVCのselected-nodeを評価できない: %v", reasonsA)
	}
	reasonsB, unknownsB := pvcNodeSchedulingConstraints(&pod, &nodeB, snapshot)
	if len(reasonsB) != 0 || !containsText(unknownsB, "動的プロビジョニング") || !podUsesPVC(&pod) {
		t.Fatalf("selected node上のgeneric ephemeral PVC評価が不正: reasons=%v unknowns=%v", reasonsB, unknownsB)
	}
}

func TestSchedulingRejectsUnownedGenericEphemeralPVC(t *testing.T) {
	pod := pendingPod("scratch-owner")
	pod.Spec.Volumes = []corev1.Volume{{Name: "cache", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{}}}}}
	pvc := corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "scratch-owner-cache", Namespace: "ns"}}
	node := schedulableNode("node-a")
	reasons, _ := pvcNodeSchedulingConstraints(&pod, &node, &kube.Snapshot{PersistentVolumeClaims: []corev1.PersistentVolumeClaim{pvc}})
	if !containsText(reasons, "このPodによって所有されていません") {
		t.Fatalf("無関係な同名PVCをgeneric ephemeral volumeへ使用した: %v", reasons)
	}
}

func TestGenericEphemeralPVCParticipatesInRootCauseGraph(t *testing.T) {
	pod := pendingPod("graph-scratch")
	pod.Spec.Volumes = []corev1.Volume{{Name: "cache", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{}}}}}
	graph := buildDependencyGraph(&kube.Snapshot{Pods: []corev1.Pod{pod}})
	paths := graph.descendants("PersistentVolumeClaim/ns/graph-scratch-cache", "")
	if len(paths) != 1 || paths[0].Resource != "Pod/ns/graph-scratch" || paths[0].Relations[0] != "generic-ephemeral-volume" {
		t.Fatalf("generic ephemeral PVCからPodへの依存関係がない: %#v", paths)
	}
}

func TestGenericEphemeralPVCIsNotReportedUnused(t *testing.T) {
	pod := pendingPod("unused-scratch")
	pod.Spec.Volumes = []corev1.Volume{{Name: "cache", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{}}}}}
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["pvcs"] = kube.FetchStatus{Available: true}
	snapshot.Pods = []corev1.Pod{pod}
	snapshot.PersistentVolumeClaims = []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "unused-scratch-cache", Namespace: "ns"}}}
	if findings := UnusedFindings(snapshot, false); len(findings) != 0 {
		t.Fatalf("generic ephemeral volume用PVCを未使用扱いした: %#v", findings)
	}
}

func TestFailedPodPhaseIsSymptomNotConfirmedRootCause(t *testing.T) {
	finding := model.NewFinding(model.Issue, "K8S.POD.FAILED_PHASE", "Pod", "Pod/ns/api", "Failed", "failed-phase", "failed", 100)
	state := model.NewState()
	state.Add(finding)
	Correlate(&kube.Snapshot{}, state)
	if len(state.RootCauses) != 1 || state.RootCauses[0].Confirmed || state.RootCauses[0].Confidence != 70 {
		t.Fatalf("Pod phase=Failedという症状を確定根本原因にした: %#v", state.RootCauses)
	}
}

func TestControllerRulesIgnoreStaleObservedGeneration(t *testing.T) {
	deployment := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Generation: 2},
		Spec:       appsv1.DeploymentSpec{Replicas: int32Pointer(3)},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 1, ReadyReplicas: 0, Conditions: []appsv1.DeploymentCondition{{
			Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded",
		}}},
	}
	hpaObserved := int64(1)
	hpa := autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Generation: 2},
		Spec:       autoscalingv2.HorizontalPodAutoscalerSpec{MaxReplicas: 3},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{ObservedGeneration: &hpaObserved, CurrentReplicas: 3, DesiredReplicas: 3,
			Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{{Type: autoscalingv2.AbleToScale, Status: corev1.ConditionFalse}}},
	}
	pdb := policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Generation: 2},
		Status:     policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 1, CurrentHealthy: 0, DesiredHealthy: 3},
	}
	snapshot := &kube.Snapshot{Deployments: []appsv1.Deployment{deployment}, HPAs: []autoscalingv2.HorizontalPodAutoscaler{hpa}, PodDisruptionBudgets: []policyv1.PodDisruptionBudget{pdb}}
	if findings := (WorkloadRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); len(findings) != 0 {
		t.Fatalf("未反映Deployment statusを異常扱いした: %#v", findings)
	}
	if findings := (HPARule{}).Evaluate(context.Background(), snapshot, config.Defaults()); len(findings) != 0 {
		t.Fatalf("未反映HPA statusを異常扱いした: %#v", findings)
	}
	if findings := (PDBRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); len(findings) != 0 {
		t.Fatalf("未反映PDB statusを異常扱いした: %#v", findings)
	}
	if message, degraded := degradedResourceMessage(snapshot, "Deployment/ns/api"); degraded || message != "" {
		t.Fatalf("未反映Deployment statusを波及影響にした: %q", message)
	}
}

func TestDeploymentNormalRolloutReasonsDoNotCreateReplicaWarning(t *testing.T) {
	for _, reason := range []string{"NewReplicaSetCreated", "FoundNewReplicaSet", "ReplicaSetUpdated"} {
		t.Run(reason, func(t *testing.T) {
			deployment := appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Generation: 2},
				Spec:       appsv1.DeploymentSpec{Replicas: int32Pointer(3)},
				Status: appsv1.DeploymentStatus{ObservedGeneration: 2, ReadyReplicas: 2, Conditions: []appsv1.DeploymentCondition{{
					Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: reason,
				}}},
			}
			if findings := (WorkloadRule{}).Evaluate(context.Background(), &kube.Snapshot{Deployments: []appsv1.Deployment{deployment}}, config.Defaults()); len(findings) != 0 {
				t.Fatalf("正常rollout中を警告した: %#v", findings)
			}
		})
	}
}

func TestNativeSidecarParticipatesInConfigAndLimitRangeChecks(t *testing.T) {
	restartAlways := corev1.ContainerRestartPolicyAlways
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}, Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "sidecar", RestartPolicy: &restartAlways}},
		Containers:     []corev1.Container{{Name: "app", Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}}, LivenessProbe: &corev1.Probe{}}},
	}}
	configFindings := (ConfigRiskRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, config.Defaults())
	if !hasCodeAndResource(configFindings, "K8S.CONFIG.REQUESTS_MISSING", "Pod/ns/api") || !hasCodeAndResource(configFindings, "K8S.CONFIG.LIVENESS_PROBE_MISSING", "Pod/ns/api") {
		t.Fatalf("native sidecarの構成リスクを評価できない: %#v", configFindings)
	}
	limitRange := corev1.LimitRange{ObjectMeta: metav1.ObjectMeta{Name: "limits", Namespace: "ns"}, Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
		Type: corev1.LimitTypeContainer, Min: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m")},
	}}}}
	// Missing requests are not a mismatch here because admission defaults may be
	// absent on a hand-built fixture. Give the sidecar an explicit low value.
	pod.Spec.InitContainers[0].Resources.Requests = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1m")}
	limitFindings := (LimitRangeRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}, LimitRanges: []corev1.LimitRange{limitRange}}, config.Defaults())
	if !hasCodeAndResource(limitFindings, "K8S.LIMIT_RANGE.EXISTING_POD_MISMATCH", "Pod/ns/api") {
		t.Fatalf("init/native sidecarをLimitRange評価から漏らした: %#v", limitFindings)
	}
}

func int32Pointer(value int32) *int32 { return &value }

func containsText(values []string, fragment string) bool {
	for _, value := range values {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

func TestCompletedContainersAndCompletedJobDoNotWarn(t *testing.T) {
	completed := corev1.ContainerStatus{Name: "init", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed", ExitCode: 0}}}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, InitContainerStatuses: []corev1.ContainerStatus{completed}, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	jobPod := pod
	jobPod.Name = "job"
	jobPod.OwnerReferences = []metav1.OwnerReference{{Kind: "Job", Name: "job"}}
	jobPod.Status.Phase = corev1.PodSucceeded
	jobPod.Status.InitContainerStatuses = nil
	jobPod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "main", State: completed.State}}
	findings := (PodHealthRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod, jobPod}}, config.Defaults())
	if len(findings) != 0 {
		t.Fatalf("正常なCompletedコンテナを異常扱いした: %#v", findings)
	}
}

func TestNotReadyOnlyAppliesToRunningAndTerminatingHasAgeGate(t *testing.T) {
	readyFalse := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse, Reason: "ContainersNotReady"}}
	pending := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: "ns"}, Status: corev1.PodStatus{Phase: corev1.PodPending, Conditions: readyFalse}}
	freshDeletion := metav1.NewTime(time.Now().Add(-time.Minute))
	running := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "running", Namespace: "ns", DeletionTimestamp: &freshDeletion}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: readyFalse}}
	findings := (PodHealthRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pending, running}}, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.POD.PENDING_STATE", "Pod/ns/pending") {
		t.Fatalf("Pending所見がない: %#v", findings)
	}
	if hasCodeAndResource(findings, "K8S.POD.NOT_READY", "Pod/ns/pending") || hasCodeAndResource(findings, "K8S.POD.TERMINATING_STATE", "Pod/ns/running") {
		t.Fatalf("起動中または削除直後を過検知した: %#v", findings)
	}
	if !hasCodeAndResource(findings, "K8S.POD.NOT_READY", "Pod/ns/running") {
		t.Fatalf("RunningのNotReadyを検出できない: %#v", findings)
	}
}

func TestNominatedNodeNeedsPositivePreemptionEvidence(t *testing.T) {
	pod := pendingPod("nominated")
	pod.Status.NominatedNodeName = "node-a"
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, Nodes: []corev1.Node{schedulableNode("node-a")}}
	finding := schedulingFinding(t, snapshot, "K8S.SCHEDULING.NOMINATED_NODE_PENDING")
	if finding.Reason != "NominatedNodePending" {
		t.Fatalf("preemptionと誤断定した: %#v", finding)
	}
	snapshot.Events = []corev1.Event{{ObjectMeta: metav1.ObjectMeta{Namespace: "ns"}, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "ns", Name: pod.Name, UID: pod.UID}, Reason: "Preempted", Message: "preemption victim is terminating; nominated node-a"}}
	_ = schedulingFinding(t, snapshot, "K8S.SCHEDULING.PREEMPTION_PENDING")
}

func TestFreshNominatedNodeIsNormalTransientState(t *testing.T) {
	pod := pendingPod("fresh-nominated")
	pod.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Minute))
	pod.Status.NominatedNodeName = "node-a"
	findings := (SchedulingRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}, Nodes: []corev1.Node{schedulableNode("node-a")}}, config.Defaults())
	if len(findings) != 0 {
		t.Fatalf("指名直後の正常な遷移を警告した: %#v", findings)
	}
}

func TestDominantSchedulingCauseMustBeCommonToAllNodes(t *testing.T) {
	assessments := []nodeAssessment{
		{Node: "selector-node", Reasons: []string{"nodeSelector不一致"}, Categories: map[schedulingCategory]struct{}{categoryNodeAffinity: {}}},
		{Node: "capacity-a", Reasons: []string{"cpu不足"}, Categories: map[schedulingCategory]struct{}{categoryResources: {}}},
		{Node: "capacity-b", Reasons: []string{"cpu不足"}, Categories: map[schedulingCategory]struct{}{categoryResources: {}}},
	}
	if code, _ := dominantSchedulingCode(assessments); code != "K8S.SCHEDULING.NO_AVAILABLE_NODE" {
		t.Fatalf("一部NodeだけのnodeSelector理由を支配原因にした: %s", code)
	}
	assessments[0].Categories = map[schedulingCategory]struct{}{categoryResources: {}}
	if code, _ := dominantSchedulingCode(assessments); code != "K8S.SCHEDULING.INSUFFICIENT_RESOURCES" {
		t.Fatalf("全Node共通のresource不足を選べない: %s", code)
	}
}

func TestFeasibleNodeCountIncludesNodesWithUnknownConstraints(t *testing.T) {
	pod := pendingPod("unknown-allocatable-pods")
	node := schedulableNode("node-a")
	delete(node.Status.Allocatable, corev1.ResourcePods)
	finding := schedulingFinding(t, &kube.Snapshot{Pods: []corev1.Pod{pod}, Nodes: []corev1.Node{node}}, "K8S.SCHEDULING.FAILED_SCHEDULING_REPORTED")
	if !strings.Contains(finding.Message, "1台中 1台") || !strings.Contains(finding.Message, "未評価") {
		t.Fatalf("配置可能と未評価を分離できていない: %#v", finding)
	}
}

func TestOptionalFetchFailureKeepsSchedulingPartialEvaluation(t *testing.T) {
	pod := pendingPod("partial")
	snapshot := kube.NewSnapshot()
	snapshot.Pods = []corev1.Pod{pod}
	snapshot.Nodes = []corev1.Node{schedulableNode("node-a")}
	for _, key := range []string{"pods", "nodes", "pvcs", "storageclasses", "events"} {
		snapshot.Statuses[key] = kube.FetchStatus{Available: true}
	}
	snapshot.Statuses["all_pods"] = kube.FetchStatus{Available: false, Status: kube.StatusForbidden, Reason: "RBAC Forbidden"}
	state := model.NewState()
	NewRegistry(SchedulingRule{}).Run(context.Background(), snapshot, config.Defaults(), state)
	if !hasCodeAndResource(state.Findings, "K8S.API.PARTIAL_UNAVAILABLE", "Rule/pending-scheduling") || !hasCodeAndResource(state.Findings, "K8S.SCHEDULING.FAILED_SCHEDULING_REPORTED", "Pod/ns/partial") {
		t.Fatalf("任意取得失敗でScheduling全体が止まった: %#v", state.Findings)
	}
	for _, finding := range state.Findings {
		if finding.RuleID != "pending-scheduling" {
			t.Fatalf("生成元ルールIDが付与されていない: %#v", finding)
		}
	}
}

func TestUnusedReferencesIncludeWorkloadTemplatesAndServiceAccounts(t *testing.T) {
	secretRef := corev1.LocalObjectReference{Name: "app-secret"}
	template := corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		ServiceAccountName: "builder",
		Containers:         []corev1.Container{{Name: "app", EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}}}}}},
		ImagePullSecrets:   []corev1.LocalObjectReference{secretRef},
		Volumes:            []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}}},
	}}
	cronTemplate := corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "job", EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cron-secret"}}}}}}}}
	snapshot := kube.NewSnapshot()
	for _, key := range []string{"configmaps", "secrets", "pvcs", "serviceaccounts"} {
		snapshot.Statuses[key] = kube.FetchStatus{Available: true}
	}
	snapshot.Deployments = []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"}, Spec: appsv1.DeploymentSpec{Template: template}}}
	snapshot.CronJobs = []batchv1.CronJob{{ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "ns"}, Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: cronTemplate}}}}}
	snapshot.ConfigMaps = []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "ns"}}}
	snapshot.Secrets = []kube.SecretProjection{{Name: "app-secret", Namespace: "ns"}, {Name: "cron-secret", Namespace: "ns"}, {Name: "sa-pull", Namespace: "ns"}}
	snapshot.PersistentVolumeClaims = []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "ns"}}}
	snapshot.ServiceAccounts = []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "builder", Namespace: "ns"}, ImagePullSecrets: []corev1.LocalObjectReference{{Name: "sa-pull"}}}}
	if findings := UnusedFindings(snapshot, false); len(findings) != 0 {
		t.Fatalf("Workload/ServiceAccount参照を未使用扱いした: %#v", findings)
	}
}

func TestUnusedCandidatesExcludeHelmAndSystemNamespaceOnlyForClusterScope(t *testing.T) {
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["secrets"] = kube.FetchStatus{Available: true}
	snapshot.Secrets = []kube.SecretProjection{
		{Name: "sh.helm.release.v1.api.v1", Namespace: "prod", Type: corev1.SecretType("helm.sh/release.v1")},
		{Name: "controller-state", Namespace: "kube-system", Type: corev1.SecretTypeOpaque},
	}
	if findings := UnusedFindings(snapshot, true); len(findings) != 0 {
		t.Fatalf("クラスタ全体scanでHelm/system resourceを候補にした: %#v", findings)
	}
	findings := UnusedFindings(snapshot, false)
	if len(findings) != 1 || findings[0].Resource != "Secret/kube-system/controller-state" {
		t.Fatalf("明示namespace scanでもsystem resourceを除外した: %#v", findings)
	}
}

func TestRootCauseCountsOnlyDegradedDescendants(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"app": "api"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "api", EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "db"}}}}}}}}
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}}}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, Services: []corev1.Service{service}}
	state := model.NewState()
	cause := model.NewFinding(model.Issue, "K8S.DEPENDENCY.MISSING_OBJECT", "関連リソース", "Secret/ns/db", "NotFound", "Secret/db", "missing", 100)
	symptom := model.NewFinding(model.Warning, "K8S.SERVICE.NO_READY_ENDPOINT", "Service", "Service/ns/api", "NoReadyEndpoint", "ready-endpoint-zero", "no endpoint", 85)
	state.Add(cause)
	state.Add(symptom)
	state.Add(model.NewFinding(model.Candidate, "K8S.CONFIG.REQUESTS_MISSING", "構成リスク", "Pod/ns/api", "RequestsMissing", "api/requests", "requests missing", 40))
	Correlate(snapshot, state)
	if len(state.RootCauses) == 0 || len(state.RootCauses[0].DirectImpacts) != 0 || len(state.RootCauses[0].PropagatedImpacts) != 1 {
		t.Fatalf("健全な中継Podをimpactとして数えた: %#v", state.RootCauses)
	}
	if path := state.RootCauses[0].PropagatedImpacts[0].Path; len(path) != 3 || path[1] != "Pod/ns/api" {
		t.Fatalf("健全な中継経路が失われた: %#v", path)
	}
}

func TestLogSignatureBecomesRootCauseEvidence(t *testing.T) {
	state := model.NewState()
	cause := model.NewFinding(model.Issue, "K8S.POD.ABNORMAL_STATE", "Pod", "Pod/ns/api", "CrashLoopBackOff", "app/CrashLoopBackOff", "Pod ns/api / container app: CrashLoopBackOff", 100)
	logs := AnalyzeLogs("ns", "api", "previous", "panic: runtime error: invalid memory address\n", 20)
	if len(logs) != 1 {
		t.Fatalf("panicログを検出できない: %#v", logs)
	}
	state.Add(cause)
	state.Add(logs[0])
	Correlate(&kube.Snapshot{}, state)
	if len(state.RootCauses) != 1 {
		t.Fatalf("Pod異常のRoot Causeがない: %#v", state.RootCauses)
	}
	root := state.RootCauses[0]
	if !evidenceContains(model.Finding{Evidence: root.Evidence}, "Goのpanic") || !evidenceContains(model.Finding{Evidence: root.Evidence}, "panic: runtime error") {
		t.Fatalf("ログシグネチャがRoot Cause根拠へ入らない: %#v", root.Evidence)
	}
	if !contains(root.RelatedFindingIDs, logs[0].ID) {
		t.Fatalf("ログFindingがRoot Causeへ関連付かない: %#v", root.RelatedFindingIDs)
	}
}

func TestNodeConditionAllowlistAndNetworkUnavailable(t *testing.T) {
	node := schedulableNode("node-a")
	node.Status.Conditions = []corev1.NodeCondition{
		{Type: corev1.NodeNetworkUnavailable, Status: corev1.ConditionTrue, Reason: "NoRoute"},
		{Type: corev1.NodeConditionType("VendorHealthy"), Status: corev1.ConditionTrue, Reason: "Healthy"},
	}
	findings := (NodeRule{}).Evaluate(context.Background(), &kube.Snapshot{Nodes: []corev1.Node{node}}, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.NODE.CONDITION", "Node/node-a") || !hasCodeAndResource(findings, "K8S.NODE.UNKNOWN_CONDITION", "Node/node-a") {
		t.Fatalf("Node condition allowlistが不正: %#v", findings)
	}
}

func TestEndpointSliceCanConfirmNamedTargetPort(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"app": "api"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "api"}}}}
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}, Ports: []corev1.ServicePort{{Name: "web", Port: 80, TargetPort: intstr.FromString("http")}}}}
	portName, port, protocol := "web", int32(8080), corev1.ProtocolTCP
	slice := discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"kubernetes.io/service-name": "api"}}, Ports: []discoveryv1.EndpointPort{{Name: &portName, Port: &port, Protocol: &protocol}}, Endpoints: []discoveryv1.Endpoint{{}}}
	findings := (ServiceRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}, Services: []corev1.Service{service}, EndpointSlices: []discoveryv1.EndpointSlice{slice}}, config.Defaults())
	if hasCodeAndResource(findings, "K8S.SERVICE.TARGET_PORT_UNRESOLVED", "Service/ns/api") {
		t.Fatalf("EndpointSliceで解決済みのtargetPortを異常扱いした: %#v", findings)
	}
}

func TestNamedTargetPortFindingExplainsTheComparedConfiguration(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-abc", Namespace: "ns", Labels: map[string]string{"app": "api", "tier": "backend"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "api", Ports: []corev1.ContainerPort{
			{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
			{Name: "admin", ContainerPort: 9090, Protocol: corev1.ProtocolUDP},
		}}}},
	}
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"tier": "backend", "app": "api"},
			Ports:    []corev1.ServicePort{{Name: "web", Port: 80, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromString("admin")}},
		},
	}
	slice := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"kubernetes.io/service-name": "api"}},
		Endpoints:  []discoveryv1.Endpoint{{}},
	}
	findings := (ServiceRule{}).Evaluate(context.Background(), &kube.Snapshot{
		Pods: []corev1.Pod{pod}, Services: []corev1.Service{service}, EndpointSlices: []discoveryv1.EndpointSlice{slice},
	}, config.Defaults())
	var finding model.Finding
	for _, value := range findings {
		if value.Code == "K8S.SERVICE.TARGET_PORT_UNRESOLVED" {
			finding = value
			break
		}
	}
	if finding.Code == "" {
		t.Fatalf("名前付きtargetPort不一致を検出できない: %#v", findings)
	}
	for _, want := range []string{"ポート \"web\"（80/TCP）", "targetPort に \"admin\" が指定されています", "\"admin\" という名前の TCP containerPort が定義されていない"} {
		if !strings.Contains(finding.Message, want) {
			t.Fatalf("所見に比較内容%qがない: %q", want, finding.Message)
		}
	}
	for _, want := range []string{
		"Serviceポート \"web\"（80/TCP） → targetPort \"admin\"",
		"Serviceのselector: app=api, tier=backend",
		"selectorに一致したPod: 1件（ns/api-abc）",
		"TCP の containerPort 名: http",
		"targetPort \"admin\" と同名の TCP containerPort は見つかりませんでした（0件）",
		"EndpointSliceからも転送先ポートを確認できませんでした",
	} {
		if !evidenceContains(finding, want) {
			t.Fatalf("targetPort判定の根拠%qがない: %#v", want, finding.Evidence)
		}
	}
}

func TestRepresentativeFindingMessagesAreNaturalAndExplainTheTrigger(t *testing.T) {
	now := time.Now()
	failedPod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "failed", Namespace: "ns"},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted", Message: "disk pressure"},
	}
	replicas := int32(3)
	deployment := appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Generation: 1},
		Spec:       appsv1.DeploymentSpec{Replicas: &replicas},
		Status:     appsv1.DeploymentStatus{ObservedGeneration: 1, ReadyReplicas: 1},
	}
	hpa := autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Spec:       autoscalingv2.HorizontalPodAutoscalerSpec{MaxReplicas: 10},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{Conditions: []autoscalingv2.HorizontalPodAutoscalerCondition{{
			Type: autoscalingv2.AbleToScale, Status: corev1.ConditionFalse, Reason: "FailedGetScale",
		}}},
	}
	pdb := policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Generation: 1},
		Status:     policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 1, CurrentHealthy: 1, DesiredHealthy: 2},
	}
	tlsSnapshot := &kube.Snapshot{
		ServerTime: now,
		Secrets: []kube.SecretProjection{{
			Namespace: "ns", Name: "tls", Type: corev1.SecretTypeTLS,
			TLSCert: certificatePEMWindow(t, now.Add(-24*time.Hour), now.Add(-time.Hour), 300),
		}},
	}
	pvc := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "ns"},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}

	cases := []struct {
		name     string
		finding  model.Finding
		required []string
	}{
		{"Pod", findingWithCode(t, (PodHealthRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{failedPod}}, config.Defaults()), "K8S.POD.FAILED_PHASE"), []string{"Pod ns/failed の状態（phase）は Failed です", "Kubernetesが報告した理由: Evicted", "詳細: disk pressure"}},
		{"Deployment", findingWithCode(t, (WorkloadRule{}).Evaluate(context.Background(), &kube.Snapshot{Deployments: []appsv1.Deployment{deployment}}, config.Defaults()), "K8S.WORKLOAD.REPLICAS_UNAVAILABLE"), []string{"Deployment ns/api", "Ready状態のレプリカ数は 1/3 です"}},
		{"HPA", findingWithCode(t, (HPARule{}).Evaluate(context.Background(), &kube.Snapshot{HPAs: []autoscalingv2.HorizontalPodAutoscaler{hpa}}, config.Defaults()), "K8S.HPA.CONDITION"), []string{"状態条件（condition） \"AbleToScale\" は False です", "Kubernetesが報告した理由: FailedGetScale"}},
		{"PDB", findingWithCode(t, (PDBRule{}).Evaluate(context.Background(), &kube.Snapshot{PodDisruptionBudgets: []policyv1.PodDisruptionBudget{pdb}}, config.Defaults()), "K8S.PDB.HEALTH_BELOW_DESIRED"), []string{"正常なPodが 1個", "必要な 2個"}},
		{"TLS", findingWithCode(t, (TLSRule{}).Evaluate(context.Background(), tlsSnapshot, config.Defaults()), "K8S.TLS.CERT_EXPIRED"), []string{"TLS証明書 ns/tls", "有効期限", "を過ぎています"}},
		{"PVC", findingWithCode(t, (StorageRule{}).Evaluate(context.Background(), &kube.Snapshot{PersistentVolumeClaims: []corev1.PersistentVolumeClaim{pvc}}, config.Defaults()), "K8S.PVC.NOT_BOUND"), []string{"PVC ns/data はバインドされていません", "現在のphase: Pending"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			for _, required := range test.required {
				if !strings.Contains(test.finding.Message, required) {
					t.Fatalf("診断文に発生条件%qがありません: %q", required, test.finding.Message)
				}
			}
			for _, forbidden := range []string{"phase=", "Ready condition", "currentHealthy=", "desiredHealthy=", "期限切れしています", "Failed状態", "必要な3個", "Bound状態ではありません", ": :"} {
				if strings.Contains(test.finding.Message, forbidden) {
					t.Fatalf("診断文に機械的または不自然な表現%qが残っています: %q", forbidden, test.finding.Message)
				}
			}
		})
	}
}

func TestNormalDeploymentRolloutDoesNotWarnReplicaShortage(t *testing.T) {
	replicas := int32(3)
	deployment := appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}, Spec: appsv1.DeploymentSpec{Replicas: &replicas}, Status: appsv1.DeploymentStatus{ReadyReplicas: 2, Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "ReplicaSetUpdated"}}}}
	if findings := (WorkloadRule{}).Evaluate(context.Background(), &kube.Snapshot{Deployments: []appsv1.Deployment{deployment}}, config.Defaults()); len(findings) != 0 {
		t.Fatalf("正常rollout中のReady不足を警告した: %#v", findings)
	}
}

func TestControlPlaneOnlyTreatsNegativeHealthLinesAsFailures(t *testing.T) {
	snapshot := &kube.Snapshot{Readyz: "[+]failed-name ok\nok", Livez: "[-]etcd failed: reason withheld"}
	findings := (ControlPlaneRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if len(findings) != 1 || findings[0].Code != "K8S.CONTROL_PLANE.LIVEZ_FAILED" {
		t.Fatalf("readyz/livez解析が不正: %#v", findings)
	}
}

func TestControlPlaneHTTP5xxIsIssueEvenWithoutVerboseFailureLine(t *testing.T) {
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["readyz"] = kube.FetchStatus{Available: false, Status: kube.StatusError, HTTPCode: 500, Reason: "Internal Server Error"}
	snapshot.Readyz = "health endpoint failed"
	findings := (ControlPlaneRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasSeverityCode(findings, model.Issue, "K8S.CONTROL_PLANE.READYZ_FAILED") {
		t.Fatalf("readyz HTTP 500を確定異常にできない: %#v", findings)
	}
}

func TestLoadBalancerPendingCandidatesHaveAgeGate(t *testing.T) {
	fresh := metav1.NewTime(time.Now().Add(-time.Minute))
	old := metav1.NewTime(time.Now().Add(-20 * time.Minute))
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "lb", Namespace: "ns", CreationTimestamp: fresh}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, Selector: map[string]string{"app": "none"}}}
	ingress := networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns", CreationTimestamp: fresh}}
	if findings := (ServiceRule{}).Evaluate(context.Background(), &kube.Snapshot{Services: []corev1.Service{service}}, config.Defaults()); hasCodeAndResource(findings, "K8S.SERVICE.LOAD_BALANCER_PENDING", "Service/ns/lb") {
		t.Fatalf("作成直後のServiceをpending候補にした: %#v", findings)
	}
	if findings := (IngressRule{}).Evaluate(context.Background(), &kube.Snapshot{Ingresses: []networkingv1.Ingress{ingress}}, config.Defaults()); len(findings) != 0 {
		t.Fatalf("作成直後のIngressをpending候補にした: %#v", findings)
	}
	service.CreationTimestamp, ingress.CreationTimestamp = old, old
	if findings := (ServiceRule{}).Evaluate(context.Background(), &kube.Snapshot{Services: []corev1.Service{service}}, config.Defaults()); !hasCodeAndResource(findings, "K8S.SERVICE.LOAD_BALANCER_PENDING", "Service/ns/lb") {
		t.Fatalf("長時間pendingのServiceを検出できない: %#v", findings)
	}
	if findings := (IngressRule{}).Evaluate(context.Background(), &kube.Snapshot{Ingresses: []networkingv1.Ingress{ingress}}, config.Defaults()); !hasCodeAndResource(findings, "K8S.INGRESS.LOAD_BALANCER_PENDING", "Ingress/ns/web") {
		t.Fatalf("長時間pendingのIngressを検出できない: %#v", findings)
	}
}

func TestSecretConfirmationCommandDoesNotPrintSecretYAML(t *testing.T) {
	commands := confirmationCommands(model.NewFinding(model.Issue, "K8S.DEPENDENCY.MISSING_KEY", "関連リソース", "Secret/prod/db", "MissingKey", "db/password", "missing", 100))
	if len(commands) != 1 || !strings.Contains(commands[0], "describe secret") || strings.Contains(commands[0], "-o yaml") {
		t.Fatalf("Secret値を表示し得る確認コマンド: %#v", commands)
	}
}

func TestOptionalDependencyMissingIsExplicitAndRequiredWins(t *testing.T) {
	optional := true
	required := false
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", EnvFrom: []corev1.EnvFromSource{
		{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}, Optional: &optional}},
	}}}}}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns"}}}}
	findings := (DependencyRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.DEPENDENCY.OPTIONAL_OBJECT_MISSING", "ConfigMap/ns/settings") {
		t.Fatalf("存在しないoptional ConfigMapが明示されない: %#v", findings)
	}
	if len(findings) != 1 || findings[0].Severity != model.Candidate || !strings.Contains(findings[0].Message, "リソース自体") {
		t.Fatalf("optional ConfigMapを確定異常にせず明示する必要がある: %#v", findings)
	}
	pod.Spec.Containers[0].EnvFrom = append(pod.Spec.Containers[0].EnvFrom, corev1.EnvFromSource{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}, Optional: &required}})
	snapshot.Pods = []corev1.Pod{pod}
	findings = (DependencyRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.DEPENDENCY.MISSING_OBJECT", "ConfigMap/ns/settings") {
		t.Fatalf("required参照がoptionalに握りつぶされた: %#v", findings)
	}
	if hasCodeAndResource(findings, "K8S.DEPENDENCY.OPTIONAL_OBJECT_MISSING", "ConfigMap/ns/settings") {
		t.Fatalf("required参照とoptional候補が二重表示された: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Code != "K8S.DEPENDENCY.MISSING_OBJECT" || finding.Resource != "ConfigMap/ns/settings" {
			continue
		}
		if !strings.Contains(finding.Message, "ConfigMap ns/settings") || !strings.Contains(finding.Message, "リソース自体が未作成か、すでに削除") {
			t.Fatalf("存在しない必須ConfigMapの説明が曖昧: %q", finding.Message)
		}
		if !evidenceContains(finding, "一致するリソースは0件") {
			t.Fatalf("存在しないと判定した根拠がない: %#v", finding.Evidence)
		}
	}
}

func TestUnrelatedConfigMapDoesNotSatisfyNamedReference(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"}, Spec: corev1.PodSpec{
		ServiceAccountName: "default",
		Containers: []corev1.Container{{Name: "app", EnvFrom: []corev1.EnvFromSource{{
			ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "app-settings"}},
		}}}},
	}}
	snapshot := &kube.Snapshot{
		Pods:            []corev1.Pod{pod},
		ConfigMaps:      []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "kube-root-ca.crt", Namespace: "ns"}}},
		ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns"}}},
	}
	findings := (DependencyRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.DEPENDENCY.MISSING_OBJECT", "ConfigMap/ns/app-settings") {
		t.Fatalf("無関係なkube-root-ca.crtを参照先ConfigMapと誤認した: %#v", findings)
	}
}

func TestVolumePluginSecretReferencesAreDependencies(t *testing.T) {
	secretRef := func(name string) *corev1.LocalObjectReference {
		return &corev1.LocalObjectReference{Name: name}
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "storage-app", Namespace: "ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
			Volumes: []corev1.Volume{
				{Name: "csi", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{NodePublishSecretRef: secretRef("csi-secret")}}},
				{Name: "rbd", VolumeSource: corev1.VolumeSource{RBD: &corev1.RBDVolumeSource{SecretRef: secretRef("rbd-secret")}}},
				{Name: "cinder", VolumeSource: corev1.VolumeSource{Cinder: &corev1.CinderVolumeSource{SecretRef: secretRef("cinder-secret")}}},
				{Name: "cephfs", VolumeSource: corev1.VolumeSource{CephFS: &corev1.CephFSVolumeSource{SecretRef: secretRef("cephfs-secret")}}},
				{Name: "flex", VolumeSource: corev1.VolumeSource{FlexVolume: &corev1.FlexVolumeSource{SecretRef: secretRef("flex-secret")}}},
				{Name: "iscsi", VolumeSource: corev1.VolumeSource{ISCSI: &corev1.ISCSIVolumeSource{SecretRef: secretRef("iscsi-secret")}}},
				{Name: "scaleio", VolumeSource: corev1.VolumeSource{ScaleIO: &corev1.ScaleIOVolumeSource{SecretRef: secretRef("scaleio-secret")}}},
				{Name: "storageos", VolumeSource: corev1.VolumeSource{StorageOS: &corev1.StorageOSVolumeSource{SecretRef: secretRef("storageos-secret")}}},
				{Name: "azure", VolumeSource: corev1.VolumeSource{AzureFile: &corev1.AzureFileVolumeSource{SecretName: "azure-secret"}}},
			},
		},
	}
	want := map[string]string{
		"csi-secret":       "volume/csi.csi.nodePublishSecretRef",
		"rbd-secret":       "volume/rbd.rbd.secretRef",
		"cinder-secret":    "volume/cinder.cinder.secretRef",
		"cephfs-secret":    "volume/cephfs.cephfs.secretRef",
		"flex-secret":      "volume/flex.flexVolume.secretRef",
		"iscsi-secret":     "volume/iscsi.iscsi.secretRef",
		"scaleio-secret":   "volume/scaleio.scaleIO.secretRef",
		"storageos-secret": "volume/storageos.storageOS.secretRef",
		"azure-secret":     "volume/azure.azureFile.secretName",
	}
	for _, dependency := range podDependencies(&pod) {
		if dependency.Kind != "Secret" {
			continue
		}
		if source, exists := want[dependency.Name]; exists {
			if dependency.Namespace != "ns" || dependency.Optional || dependency.Source != source {
				t.Errorf("Secret依存 %s が不正: %#v", dependency.Name, dependency)
			}
			delete(want, dependency.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("Volume Secret依存の抽出漏れ: %#v", want)
	}

	snapshot := &kube.Snapshot{
		Pods:            []corev1.Pod{pod},
		ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns"}}},
	}
	findings := (DependencyRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.DEPENDENCY.MISSING_OBJECT", "Secret/ns/csi-secret") {
		t.Fatalf("CSI nodePublishSecretRefの欠落を検出できない: %#v", findings)
	}
}

func TestClusterScopedDependenciesAreIndependentCoverageRules(t *testing.T) {
	registry := Builtins()
	ids := map[string]bool{}
	for _, rule := range registry.Rules() {
		ids[rule.Metadata().ID] = true
	}
	for _, id := range []string{"dependencies", "priority-class-dependencies", "runtime-class-dependencies", "persistent-volumes", "cronjobs", "network-policies", "limit-ranges"} {
		if !ids[id] {
			t.Fatalf("独立した依存ルール%sが登録されていない", id)
		}
	}

	priority := "critical"
	runtime := "sandboxed"
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Spec: corev1.PodSpec{
			PriorityClassName: priority, RuntimeClassName: &runtime,
			Containers: []corev1.Container{{Name: "app"}},
		},
	}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}}
	if findings := (DependencyRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); hasCodeAndResource(findings, "K8S.DEPENDENCY.MISSING_OBJECT", "PriorityClass/"+priority) || hasCodeAndResource(findings, "K8S.DEPENDENCY.MISSING_OBJECT", "RuntimeClass/"+runtime) {
		t.Fatalf("namespaced依存ルールがcluster依存まで評価した: %#v", findings)
	}
	if findings := (PriorityClassDependencyRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); !hasCodeAndResource(findings, "K8S.DEPENDENCY.MISSING_OBJECT", "PriorityClass/"+priority) {
		t.Fatalf("PriorityClass欠落を検出できない: %#v", findings)
	}
	if findings := (RuntimeClassDependencyRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); !hasCodeAndResource(findings, "K8S.DEPENDENCY.MISSING_OBJECT", "RuntimeClass/"+runtime) {
		t.Fatalf("RuntimeClass欠落を検出できない: %#v", findings)
	}
}

func TestMetricsCoverageAndStableUnavailableCodesAreIndependent(t *testing.T) {
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["node_metrics"] = kube.FetchStatus{Available: false, Status: kube.StatusNotFound, Reason: "NotFound: metrics API"}
	snapshot.Statuses["pod_metrics"] = kube.FetchStatus{Available: true, Status: kube.StatusOK}
	state := model.NewState()
	registry := NewRegistry(NodeMetricsRule{}, PodMetricsRule{})
	cfg := config.Defaults()
	cfg.Mode = "all"
	registry.Run(context.Background(), snapshot, cfg, state)

	ok, unavailable, total := state.CoverageCounts()
	if ok != 1 || unavailable != 1 || total != 2 {
		t.Fatalf("metrics Coverage=%d/%d unavailable=%d, want 1/2 unavailable=1", ok, total, unavailable)
	}
	if len(state.Findings) != 1 || state.Findings[0].Code != "K8S.METRICS.EC8CBD04" || state.Findings[0].RuleID != "node-metrics" || state.Findings[0].Resource != "" || !strings.Contains(state.Findings[0].Message, "API未提供") {
		t.Fatalf("Node metrics取得不能FindingがPython互換でない: %#v", state.Findings)
	}
	keys := registry.RequiredKeys("all")
	if !keys["node_metrics"] || !keys["pod_metrics"] {
		t.Fatalf("metrics collector keyが有効化されない: %#v", keys)
	}
}

func TestTLSBundleChecksEveryCertificate(t *testing.T) {
	bundle := append(certificatePEM(t, time.Now().Add(-time.Hour), 1), certificatePEM(t, time.Now().Add(24*time.Hour), 2)...)
	snapshot := &kube.Snapshot{Secrets: []kube.SecretProjection{{Namespace: "ns", Name: "tls", Type: corev1.SecretTypeTLS, TLSCert: bundle}}}
	findings := (TLSRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.TLS.CERT_EXPIRED", "Secret/ns/tls") || !hasCodeAndResource(findings, "K8S.TLS.CERT_EXPIRING_SOON", "Secret/ns/tls") {
		t.Fatalf("バンドル全体を検査できていない: %#v", findings)
	}
	invalid := (TLSRule{}).Evaluate(context.Background(), &kube.Snapshot{Secrets: []kube.SecretProjection{{Namespace: "ns", Name: "bad", Type: corev1.SecretTypeTLS, TLSCert: []byte("not-a-certificate")}}}, config.Defaults())
	if len(invalid) != 1 || invalid[0].Severity != model.Issue || invalid[0].Code != "K8S.TLS.CERT_INVALID" {
		t.Fatalf("クラスタ内の不正証明書を確定異常にできていない: %#v", invalid)
	}
}

func TestTLSKeyPairValidationFailureIsAnIssue(t *testing.T) {
	snapshot := &kube.Snapshot{Secrets: []kube.SecretProjection{{
		Namespace: "ns", Name: "tls", Type: corev1.SecretTypeTLS,
		Keys:    map[string]struct{}{corev1.TLSCertKey: {}, corev1.TLSPrivateKeyKey: {}},
		TLSCert: certificatePEM(t, time.Now().Add(365*24*time.Hour), 44), TLSKeyPairError: "private key does not match public key",
	}}}
	findings := (TLSRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.TLS.KEY_PAIR_INVALID", "Secret/ns/tls") {
		t.Fatalf("TLS秘密鍵の不正・不一致を検出できない: %#v", findings)
	}
}

func TestMissingExplicitStorageClassIsAnIssue(t *testing.T) {
	className := "missing-class"
	snapshot := &kube.Snapshot{
		PersistentVolumeClaims: []corev1.PersistentVolumeClaim{{
			ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "ns"},
			Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: &className},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
		}},
		Statuses: map[string]kube.FetchStatus{"storageclasses": {Available: true}},
	}
	findings := (StorageRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasSeverityCode(findings, model.Issue, "K8S.PVC.STORAGE_CLASS_NOT_FOUND") {
		t.Fatalf("存在しないStorageClassが確定異常にならない: %#v", findings)
	}
}

func TestControlPlaneConfirmationUsesRawHealthEndpoint(t *testing.T) {
	finding := model.NewFinding(model.Issue, "K8S.CONTROL_PLANE.READYZ_FAILED", "コントロールプレーン", "ControlPlane/readyz", "Failed", "readyz", "failed", 100)
	commands := confirmationCommands(finding)
	if len(commands) != 1 || commands[0] != "kubectl get --raw='/readyz?verbose'" {
		t.Fatalf("ControlPlane確認コマンドが不正: %#v", commands)
	}
}

func TestOptionalOnlyControlPlaneCoverageHasNoSyntheticSuccess(t *testing.T) {
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["readyz"] = kube.FetchStatus{Available: false, Status: kube.StatusForbidden, Reason: "RBAC Forbidden"}
	snapshot.Statuses["livez"] = kube.FetchStatus{Available: false, Status: kube.StatusForbidden, Reason: "RBAC Forbidden"}
	state := model.NewState()
	NewRegistry(ControlPlaneRule{}).Run(context.Background(), snapshot, config.Defaults(), state)
	ok, unavailable, total := state.CoverageCounts()
	if ok != 0 || unavailable != 2 || total != 2 {
		t.Fatalf("readyz/livez全取得不能時のCoverage=%d/%d unavailable=%d, want 0/2 unavailable=2", ok, total, unavailable)
	}
}

func TestDependencyGraphConnectsPVControllerAndWebhookRelationships(t *testing.T) {
	controller := true
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "ns", OwnerReferences: []metav1.OwnerReference{{Kind: "Job", Name: "backup", Controller: &controller}}},
		Spec:       corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}}}},
	}
	job := batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "ns", OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "nightly", Controller: &controller}}}}
	pvc := corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "ns"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "pv-data"}}
	webhook := admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "policy"},
		Webhooks:   []admissionv1.ValidatingWebhook{{ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: "ns", Name: "admission"}}}},
	}
	graph := buildDependencyGraph(&kube.Snapshot{Pods: []corev1.Pod{pod}, Jobs: []batchv1.Job{job}, PersistentVolumeClaims: []corev1.PersistentVolumeClaim{pvc}, ValidatingWebhooks: []admissionv1.ValidatingWebhookConfiguration{webhook}})
	assertPath := func(start, target string) {
		t.Helper()
		for _, path := range graph.descendants(start, "") {
			if path.Resource == target {
				return
			}
		}
		t.Fatalf("依存経路 %s -> %s が存在しない", start, target)
	}
	assertPath("PersistentVolume/pv-data", "Pod/ns/db")
	assertPath("Pod/ns/db", "CronJob/ns/nightly")
	assertPath("Service/ns/admission", "ValidatingWebhookConfiguration/policy")
}

func certificatePEM(t *testing.T, notAfter time.Time, serial int64) []byte {
	return certificatePEMWindow(t, time.Now().Add(-24*time.Hour), notAfter, serial)
}

func certificatePEMWindow(t *testing.T, notBefore, notAfter time.Time, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test"}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func evidenceContains(finding model.Finding, value string) bool {
	for _, evidence := range finding.Evidence {
		if strings.Contains(evidence.Value, value) {
			return true
		}
	}
	return false
}

func findingWithCode(t *testing.T, findings []model.Finding, code string) model.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code {
			return finding
		}
	}
	t.Fatalf("所見 %s がありません: %#v", code, findings)
	return model.Finding{}
}

func hasCodeAndResource(findings []model.Finding, code, resource string) bool {
	for _, finding := range findings {
		if finding.Code == code && finding.Resource == resource {
			return true
		}
	}
	return false
}

// numericTargetPortPod builds a Pod that declares 8080 both as a containerPort
// and as the readinessProbe destination, and reports itself Ready. Every static
// signal therefore looks healthy no matter what the Service points at, which is
// exactly what makes a wrong numeric targetPort so hard to see.
func numericTargetPortPod() corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-abc", Namespace: "ns", Labels: map[string]string{"app": "api"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "api",
			Ports: []corev1.ContainerPort{{ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(8080), Path: "/"},
			}},
		}}},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
}

func numericTargetPortService(target int32) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "api"},
			Ports:    []corev1.ServicePort{{Name: "web", Port: 80, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(target)}},
		},
	}
}

func TestNumericTargetPortMismatchIsReportedAsCandidate(t *testing.T) {
	pod := numericTargetPortPod()
	// The EndpointSlice carries the Service's targetPort verbatim and the Pod is
	// Ready, so NO_READY_ENDPOINT stays silent. Without this rule the whole
	// diagnosis would not mention the port at all.
	port, ready := int32(8081), true
	slice := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"kubernetes.io/service-name": "api"}},
		Endpoints:  []discoveryv1.Endpoint{{Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
	}
	findings := (ServiceRule{}).Evaluate(context.Background(), &kube.Snapshot{
		Pods: []corev1.Pod{pod}, Services: []corev1.Service{numericTargetPortService(8081)}, EndpointSlices: []discoveryv1.EndpointSlice{slice},
	}, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.SERVICE.TARGET_PORT_UNDECLARED", "Service/ns/api") {
		t.Fatalf("数値targetPortの不一致を検出できない: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Code != "K8S.SERVICE.TARGET_PORT_UNDECLARED" {
			continue
		}
		if finding.Severity != model.Candidate {
			t.Fatalf("数値targetPortは宣言必須ではないためCandidateであるべき: %s", finding.Severity)
		}
		if !strings.Contains(finding.Message, "8081") || !strings.Contains(finding.Message, "設定どおり") {
			t.Fatalf("誤検知しうることが本文から読み取れない: %q", finding.Message)
		}
	}
}

func TestNumericTargetPortStaysSilentWhenThePortIsAccountedFor(t *testing.T) {
	probeOnly := numericTargetPortPod()
	probeOnly.Spec.Containers[0].Ports = nil // probe alone already proves 8080 is served
	undeclared := numericTargetPortPod()
	undeclared.Spec.Containers[0].Ports = nil
	undeclared.Spec.Containers[0].ReadinessProbe = nil // nothing declared: no evidence either way
	for _, tc := range []struct {
		name   string
		pod    corev1.Pod
		target int32
	}{
		{"containerPortに一致", numericTargetPortPod(), 8080},
		{"Probeのポートに一致", probeOnly, 8080},
		{"ポートを何も宣言していない", undeclared, 8081},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := (ServiceRule{}).Evaluate(context.Background(), &kube.Snapshot{
				Pods: []corev1.Pod{tc.pod}, Services: []corev1.Service{numericTargetPortService(tc.target)},
			}, config.Defaults())
			if hasCodeAndResource(findings, "K8S.SERVICE.TARGET_PORT_UNDECLARED", "Service/ns/api") {
				t.Fatalf("誤検知: %#v", findings)
			}
		})
	}
}

// optional:true turns a mistyped key from a startup error into silence: the
// container runs, no event is recorded, and the variable simply does not exist.
// The object being present is what separates this from a feature that is
// genuinely not deployed, which stays unreported.
func TestOptionalKeyMissingFromAnExistingObjectIsReported(t *testing.T) {
	optional := true
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{
			Name: "DATABASE_URL", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}, Key: "DATABASE_URL", Optional: &optional,
			}},
		}}}}},
	}
	configMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "ns"},
		Data:       map[string]string{"database_url": "postgres://x"},
	}
	findings := (DependencyRule{}).Evaluate(context.Background(), &kube.Snapshot{
		Pods: []corev1.Pod{pod}, ConfigMaps: []corev1.ConfigMap{configMap},
	}, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.DEPENDENCY.OPTIONAL_KEY_MISSING", "ConfigMap/ns/cm") {
		t.Fatalf("optional指定のキー名誤りを検出できない: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Code != "K8S.DEPENDENCY.OPTIONAL_KEY_MISSING" {
			continue
		}
		if finding.Severity != model.Candidate {
			t.Errorf("optionalは利用者が明示した設定なのでCandidateであるべき: %s", finding.Severity)
		}
		// The operator needs the name that does exist in order to spot the typo.
		if !hasEvidenceValue(finding, "database_url") {
			t.Errorf("実在するキー名が検出根拠にない: %#v", finding.Evidence)
		}
	}
}

func TestOptionalKeyPresentIsNotReported(t *testing.T) {
	optional := true
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{
			Name: "DATABASE_URL", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}, Key: "database_url", Optional: &optional,
			}},
		}}}}},
	}
	configMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "ns"},
		Data:       map[string]string{"database_url": "postgres://x"},
	}
	findings := (DependencyRule{}).Evaluate(context.Background(), &kube.Snapshot{
		Pods: []corev1.Pod{pod}, ConfigMaps: []corev1.ConfigMap{configMap},
	}, config.Defaults())
	if hasCodeAndResource(findings, "K8S.DEPENDENCY.OPTIONAL_KEY_MISSING", "ConfigMap/ns/cm") {
		t.Fatalf("解決できているoptional参照を誤検知した: %#v", findings)
	}
}

func hasEvidenceValue(finding model.Finding, needle string) bool {
	for _, evidence := range finding.Evidence {
		if strings.Contains(evidence.Value, needle) {
			return true
		}
	}
	return false
}

// Kubernetes keeps the last entry for a duplicated variable, so the manifest can
// state one value while the container runs with another.
func TestDuplicateEnvNameWithADifferentValueIsReported(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "debug"},
			{Name: "LOG_LEVEL", Value: "info"},
		}}}},
	}
	findings := (ConfigRiskRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.CONFIG.ENV_DUPLICATE_NAME", "Pod/ns/app") {
		t.Fatalf("env重複を検出できない: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Code == "K8S.CONFIG.ENV_DUPLICATE_NAME" && !hasEvidenceValue(finding, `value "info"`) {
			t.Errorf("どちらが採用されるのか検出根拠から分からない: %#v", finding.Evidence)
		}
	}
}

func TestDuplicateEnvNameWithTheSameValueIsNotReported(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "info"},
			{Name: "LOG_LEVEL", Value: "info"},
		}}}},
	}
	findings := (ConfigRiskRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, config.Defaults())
	if hasCodeAndResource(findings, "K8S.CONFIG.ENV_DUPLICATE_NAME", "Pod/ns/app") {
		t.Fatalf("同じ値の重複を誤検知した: %#v", findings)
	}
}

func TestDuplicateEnvEquivalentOptionalDefaultsAreNotReported(t *testing.T) {
	optionalFalse := false
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{
			{Name: "CONFIG", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}, Key: "mode",
			}}},
			{Name: "CONFIG", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}, Key: "mode", Optional: &optionalFalse,
			}}},
		}}}},
	}
	findings := (ConfigRiskRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, config.Defaults())
	if hasCodeAndResource(findings, "K8S.CONFIG.ENV_DUPLICATE_NAME", "Pod/ns/app") {
		t.Fatalf("optional未指定とfalseという同じ参照を異なる値として誤検知した: %#v", findings)
	}
}

func TestDuplicateEnvNameReportsTheActualLastOfThreeDefinitions(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "debug"},
			{Name: "LOG_LEVEL", Value: "info"},
			{Name: "LOG_LEVEL", Value: "warn"},
		}}}},
	}
	findings := (ConfigRiskRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, config.Defaults())
	count := 0
	for _, finding := range findings {
		if finding.Code != "K8S.CONFIG.ENV_DUPLICATE_NAME" {
			continue
		}
		count++
		for _, evidence := range finding.Evidence {
			if evidence.Key == "effective" && (!strings.Contains(evidence.Value, `value "warn"`) || strings.Contains(evidence.Value, `value "info"`)) {
				t.Errorf("最終定義ではない値を採用値として表示した: %q", evidence.Value)
			}
		}
	}
	if count != 1 {
		t.Fatalf("3重定義は最終値を示す1件に集約すべき: count=%d findings=%#v", count, findings)
	}
}

func webhookSnapshot(services ...corev1.Service) *kube.Snapshot {
	fail := admissionv1.Fail
	snapshot := &kube.Snapshot{
		Services: services,
		ValidatingWebhooks: []admissionv1.ValidatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "addon"},
			Webhooks: []admissionv1.ValidatingWebhook{{
				Name:          "addon.example.com",
				FailurePolicy: &fail,
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{Namespace: "addon-system", Name: "addon-webhook"},
				},
			}},
		}},
	}
	return snapshot
}

// Webhook configurations are cluster-scoped while Services are collected inside
// the requested namespace, so a namespaced run simply never sees a webhook's
// Service in another namespace. Calling that "does not exist" turned every
// healthy cluster add-on into a confirmed defect.
func TestWebhookServiceOutsideTheDiagnosedNamespaceIsUnverifiableNotMissing(t *testing.T) {
	cfg := config.Defaults()
	cfg.Namespace = "shop"
	findings := (WebhookRule{}).Evaluate(context.Background(), webhookSnapshot(), cfg)
	if hasCodeAndResource(findings, "K8S.WEBHOOK.MISSING_SERVICE", "ValidatingWebhookConfiguration/addon") {
		t.Fatalf("取得対象外のServiceを存在しないと断定した: %#v", findings)
	}
	if !hasCodeAndResource(findings, "K8S.WEBHOOK.SERVICE_UNVERIFIABLE", "ValidatingWebhookConfiguration/addon") {
		t.Fatalf("確認できない旨を報告していない: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Code == "K8S.WEBHOOK.SERVICE_UNVERIFIABLE" && finding.Severity != model.Unavailable {
			t.Errorf("確認不能として扱われていない: %s", finding.Severity)
		}
	}
}

// A Service that really is absent inside the diagnosed namespace stays a
// confirmed defect, and a cluster-wide run can still judge every webhook.
func TestWebhookMissingServiceIsStillReportedWhenItIsInScope(t *testing.T) {
	inScope := config.Defaults()
	inScope.Namespace = "addon-system"
	if !hasCodeAndResource((WebhookRule{}).Evaluate(context.Background(), webhookSnapshot(), inScope), "K8S.WEBHOOK.MISSING_SERVICE", "ValidatingWebhookConfiguration/addon") {
		t.Fatal("対象namespace内の欠落Serviceを検出できない")
	}
	if !hasCodeAndResource((WebhookRule{}).Evaluate(context.Background(), webhookSnapshot(), config.Defaults()), "K8S.WEBHOOK.MISSING_SERVICE", "ValidatingWebhookConfiguration/addon") {
		t.Fatal("全namespace実行で欠落Serviceを検出できない")
	}
	present := corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "addon-system", Name: "addon-webhook"}}
	if findings := (WebhookRule{}).Evaluate(context.Background(), webhookSnapshot(present), config.Defaults()); len(findings) != 0 {
		t.Fatalf("実在するServiceを誤検知した: %#v", findings)
	}
}
