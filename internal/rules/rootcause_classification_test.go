package rules

import (
	"reflect"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRootClassificationSeparatesSymptomsFromDirectCauses(t *testing.T) {
	for _, test := range []struct {
		code           string
		severity       model.Severity
		confidence     int
		classification string
		wantConfidence int
	}{
		{"K8S.WORKLOAD.PROGRESS_DEADLINE_EXCEEDED", model.Issue, 100, "cause_candidate", 70},
		{"K8S.WORKLOAD.REPLICA_FAILURE", model.Issue, 100, "cause_candidate", 70},
		{"K8S.POD.ABNORMAL_STATE", model.Issue, 100, "cause_candidate", 70},
		{"K8S.UNRECOGNIZED.FAILURE", model.Issue, 100, "cause_candidate", 85},
		{"K8S.DEPENDENCY.MISSING_OBJECT", model.Issue, 100, "root_cause", 100},
		{"K8S.SERVICE.TARGET_PORT_UNRESOLVED", model.Issue, 98, "root_cause", 98},
		{"K8S.LOG.X509_EXPIRED", model.Warning, 90, "cause_candidate", 85},
		{"K8S.LOG.NAME_RESOLUTION", model.Candidate, 65, "cause_candidate", 65},
		{"K8S.LOG.PERMISSION_DENIED", model.Candidate, 50, "related_candidate", 50},
	} {
		t.Run(test.code, func(t *testing.T) {
			state := model.NewState()
			finding := model.NewFinding(test.severity, test.code, "test", "Pod/ns/api", "reason", "key", "message", test.confidence)
			state.Add(finding)
			Correlate(&kube.Snapshot{}, state)
			if len(state.RootCauses) != 1 {
				t.Fatalf("原因分析から所見が欠落した: %#v", state.RootCauses)
			}
			root := state.RootCauses[0]
			if root.Classification != test.classification || root.Confidence != test.wantConfidence || root.Confirmed != (test.classification == "root_cause") {
				t.Fatalf("分類が不正: %#v", root)
			}
			if len(root.Remediations) == 0 || len(root.Commands) == 0 {
				t.Fatalf("次に確認する情報がない: %#v", root)
			}
			assessment := false
			for _, evidence := range root.Evidence {
				assessment = assessment || evidence.Kind == "assessment" && evidence.Key == "classification" && evidence.Value != ""
			}
			if !assessment || !reflect.DeepEqual(state.Findings[0], finding) {
				t.Fatal("分類理由がないか、元の所見を書き換えた")
			}
		})
	}
}

func TestRootCorrelationKeepsIndependentFaultsAndUnconfirmedSymptoms(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api"}, Spec: podSpecUsingSecret("db")}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}}
	for _, test := range []struct {
		name           string
		confidence     int
		downstreamCode string
		wantRoots      int
	}{
		{"confirmed groups symptom", 100, "K8S.POD.NOT_READY", 1},
		{"candidate cannot hide symptom", 65, "K8S.POD.NOT_READY", 2},
		{"confirmed cannot hide independent fault", 100, "K8S.INDEPENDENT.FAILURE", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := model.NewState()
			state.Add(model.NewFinding(model.Issue, "K8S.DEPENDENCY.MISSING_OBJECT", "test", "Secret/ns/db", "NotFound", "db", "missing", test.confidence))
			state.Add(model.NewFinding(model.Issue, test.downstreamCode, "test", "Pod/ns/api", "failed", "app", "failed", 100))
			Correlate(snapshot, state)
			if len(state.RootCauses) != test.wantRoots {
				t.Fatalf("独立した障害の保持が不正: %#v", state.RootCauses)
			}
		})
	}
}

func TestStandaloneLogCandidatesRemainStableAcrossFindingOrder(t *testing.T) {
	findings := append(AnalyzeLogs("ns", "api", "current", "no such host\n", 20), AnalyzeLogs("ns", "api", "previous", "panic: unexpected nil\n", 20)...)
	state := model.NewState()
	for _, finding := range findings {
		state.Add(finding)
	}
	Correlate(&kube.Snapshot{}, state)
	if len(state.RootCauses) != 2 {
		t.Fatalf("ログ候補が欠落した: %#v", state.RootCauses)
	}
	first := append([]model.RootCause{}, state.RootCauses...)
	state.Findings[0], state.Findings[1] = state.Findings[1], state.Findings[0]
	Correlate(&kube.Snapshot{}, state)
	if !reflect.DeepEqual(first, state.RootCauses) {
		t.Fatal("入力順で原因分析が変化した")
	}
}
