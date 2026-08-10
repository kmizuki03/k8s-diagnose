//lint:file-ignore SA1019 Legacy Endpoints fallback behavior is intentionally covered.

package rules

import (
	"context"
	"testing"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestEndpointSliceSuccessDoesNotFallBackToStaleEndpoints(t *testing.T) {
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}}
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["endpoint_slices"] = kube.FetchStatus{Available: true}
	snapshot.Statuses["endpoints"] = kube.FetchStatus{Available: true}
	snapshot.Endpoints = []corev1.Endpoints{{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Subsets:    []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}}}},
	}}
	if ready, fallback := serviceEndpointCounts(&service, snapshot); ready != 0 || fallback != 0 {
		t.Fatalf("EndpointSlice 0件を旧Endpointsで上書きした: ready=%d fallback=%d", ready, fallback)
	}
}

func TestEndpointSliceConditionDefaultsAndPublishNotReadySemantics(t *testing.T) {
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}}
	ready, notReady, terminating := true, false, true
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["endpoint_slices"] = kube.FetchStatus{Available: true}
	snapshot.EndpointSlices = []discoveryv1.EndpointSlice{{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"kubernetes.io/service-name": "api"}},
		Endpoints: []discoveryv1.Endpoint{
			{Conditions: discoveryv1.EndpointConditions{Ready: &ready, Terminating: &terminating}},
			{Conditions: discoveryv1.EndpointConditions{Ready: &notReady, Terminating: &terminating}},
		},
	}}
	if gotReady, fallback := serviceEndpointCounts(&service, snapshot); gotReady != 1 || fallback != 1 {
		t.Fatalf("EndpointSlice conditionの既定値またはReady条件が不正: ready=%d fallback=%d", gotReady, fallback)
	}
}

func TestEndpointSliceNilProtocolDefaultsToTCPOnly(t *testing.T) {
	portName, endpointPort := "dns", int32(5353)
	snapshot := kube.NewSnapshot()
	snapshot.EndpointSlices = []discoveryv1.EndpointSlice{{
		ObjectMeta: metav1.ObjectMeta{Name: "dns", Namespace: "ns", Labels: map[string]string{"kubernetes.io/service-name": "dns"}},
		Ports:      []discoveryv1.EndpointPort{{Name: &portName, Port: &endpointPort}},
	}}
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "dns", Namespace: "ns"}}
	tcp := corev1.ServicePort{Name: "dns", Port: 53, Protocol: corev1.ProtocolTCP}
	udp := corev1.ServicePort{Name: "dns", Port: 53, Protocol: corev1.ProtocolUDP}
	if !endpointSliceResolvesPort(&service, tcp, snapshot) {
		t.Fatal("nil EndpointPort.protocolのTCP既定値を認識できない")
	}
	if endpointSliceResolvesPort(&service, udp, snapshot) {
		t.Fatal("nil EndpointPort.protocolをUDPにも一致させた")
	}
}

func TestServiceWarnsWhenOnlyTerminatingServingEndpointsRemain(t *testing.T) {
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"app": "api"}}}
	notReady, terminating := false, true
	slice := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"kubernetes.io/service-name": "api"}},
		Endpoints:  []discoveryv1.Endpoint{{Conditions: discoveryv1.EndpointConditions{Ready: &notReady, Terminating: &terminating}}},
	}
	findings := (ServiceRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}, Services: []corev1.Service{service}, EndpointSlices: []discoveryv1.EndpointSlice{slice}}, config.Defaults())
	if len(findings) != 1 || findings[0].Code != "K8S.SERVICE.TERMINATING_ENDPOINTS_ONLY" || findings[0].Severity != model.Warning {
		t.Fatalf("終了中EndpointだけのServiceを正常扱いした: %#v", findings)
	}
}

func TestUnavailableEndpointSliceUsesLegacyEndpoints(t *testing.T) {
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}}
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["endpoint_slices"] = kube.FetchStatus{Available: false, Status: kube.StatusNotFound}
	snapshot.Statuses["endpoints"] = kube.FetchStatus{Available: true}
	snapshot.Endpoints = []corev1.Endpoints{{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Subsets:    []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}}}},
	}}
	if ready, fallback := serviceEndpointCounts(&service, snapshot); ready != 1 || fallback != 0 {
		t.Fatalf("EndpointSlice取得不能時の互換fallbackが不正: ready=%d fallback=%d", ready, fallback)
	}
}

func TestJobFailedConditionSuppressesFailureTargetDuplicate(t *testing.T) {
	job := batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "import", Namespace: "ns"},
		Status: batchv1.JobStatus{Conditions: []batchv1.JobCondition{
			{Type: batchv1.JobFailureTarget, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded", Message: "targeted"},
			{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded", Message: "failed"},
		}},
	}
	findings := (JobRule{}).Evaluate(context.Background(), &kube.Snapshot{Jobs: []batchv1.Job{job}}, config.Defaults())
	if len(findings) != 1 || findings[0].StableKey != string(batchv1.JobFailed) {
		t.Fatalf("同じJob失敗を二重計上した: %#v", findings)
	}
}

func TestEventTimeUsesLatestSeriesObservation(t *testing.T) {
	base := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	first, last, observed := metav1.NewTime(base), metav1.NewTime(base.Add(time.Minute)), metav1.NewMicroTime(base.Add(2*time.Minute))
	event := corev1.Event{FirstTimestamp: first, LastTimestamp: last, EventTime: metav1.NewMicroTime(base.Add(30 * time.Second)), Series: &corev1.EventSeries{LastObservedTime: observed}}
	if got := eventTime(&event); !got.Equal(observed.Time) {
		t.Fatalf("EventSeries.lastObservedTimeより古いeventTimeを採用した: got=%s want=%s", got, observed.Time)
	}
}

func TestNamedProbePortMustResolveWithinContainer(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "api", ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("health"), Path: "/ready"}}},
		}}},
	}
	findings := (ProbeConfigRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, config.Defaults())
	if len(findings) != 1 || findings[0].Severity != model.Issue || findings[0].Code != "K8S.PROBE.PORT_UNRESOLVED" || findings[0].Resource != "Probe/ns/api/api/readinessProbe" {
		t.Fatalf("解決不能な名前付きProbe portを確定異常にできない: %#v", findings)
	}
}

func TestProbeFailureCorrelatesToPodThroughProbeEdge(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "api", LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(8080), Path: "/health"}}},
		}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}},
	}
	state := model.NewState()
	probeFinding := model.NewFinding(model.Warning, "K8S.PROBE.HTTP_FAILED", "Probe確認", "Probe/ns/api/api/livenessProbe", "livenessProbe", "pod/livenessProbe/8080", "HTTP 500", 72)
	state.Add(probeFinding)
	state.Add(model.NewFinding(model.Warning, "K8S.POD.NOT_READY", "Pod", "Pod/ns/api", "ContainersNotReady", "ready", "NotReady", 85))
	Correlate(&kube.Snapshot{Pods: []corev1.Pod{pod}}, state)
	if len(state.RootCauses) == 0 {
		t.Fatal("Probe失敗がRoot Cause候補にならない")
	}
	root := state.RootCauses[0]
	if root.Cause.ID != probeFinding.ID || len(root.DirectImpacts) != 1 || root.DirectImpacts[0].Resource != "Pod/ns/api" {
		t.Fatalf("Probe→Podの直接影響が欠落: %#v", root)
	}
	if len(root.DirectImpacts[0].PathRelations) != 1 || root.DirectImpacts[0].PathRelations[0] != "probe-controls" || len(root.Remediations) == 0 || len(root.Commands) != 2 {
		t.Fatalf("Probeの経路・修正候補・確認コマンドが欠落: %#v", root)
	}
}
