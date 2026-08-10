package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/baseline"
	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	"github.com/kmizuki03/k8s-diagnose/internal/rules"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func TestRefreshPodTargetRejectsReplacement(t *testing.T) {
	current := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-2")}}
	runner := &Runner{Clients: &kube.Clients{Kube: kubefake.NewSimpleClientset(current)}}
	selected := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-1")}}
	if _, err := runner.refreshPodTarget(context.Background(), selected); err == nil {
		t.Fatal("同名で再作成されたPodへのdebugを許可した")
	}
}

func TestInterpretCanIResultTreatsAuthorizationDenialAsAValidAnswer(t *testing.T) {
	allowed, err := interpretCanIResult([]byte("no\n"), errors.New("exit status 1"))
	if err != nil || allowed {
		t.Fatalf("権限拒否をコマンド障害と誤認した: allowed=%v err=%v", allowed, err)
	}
	allowed, err = interpretCanIResult([]byte("yes\n"), nil)
	if err != nil || !allowed {
		t.Fatalf("許可応答を解釈できない: allowed=%v err=%v", allowed, err)
	}
	if _, err := interpretCanIResult([]byte("API unavailable"), errors.New("exit status 1")); err == nil {
		t.Fatal("実際のkubectl障害を権限拒否として握りつぶした")
	}
}

func TestLateHistoryOrConnectFindingReceivesBaselineAcknowledgement(t *testing.T) {
	state := model.NewState()
	finding := model.NewFinding(model.Warning, "K8S.HISTORY.RESTART_GROWTH", "履歴トレンド", "Pod/ns/api", "restart_growth", "restart_growth", "増加", 95)
	state.Add(finding)
	runner := &Runner{Baseline: baseline.Baseline{Path: "baseline.ini", Rules: []baseline.Rule{{
		ID: "known-restart", Code: finding.Code, Resource: finding.Resource,
		Expires: "2099-12-31", Reason: "既知の負荷試験",
	}}}}
	runner.applyBaselineToLateFindings(&kube.Snapshot{}, state)
	values := state.BySeverity(model.Warning, false)
	if len(values) != 1 || !values[0].Acknowledged {
		t.Fatalf("後段所見へbaselineが適用されない: %#v", values)
	}
}

func TestWorkloadBaselineUsesHealthyOwnerGraphForLatePodFinding(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-abc", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-rs"}}}}
	replicaSet := appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-rs", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api"}}}}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, ReplicaSets: []appsv1.ReplicaSet{replicaSet}}
	state := model.NewState()
	finding := model.NewFinding(model.Warning, "K8S.CONNECT.HTTP_FAILED", "接続確認", "Pod/ns/api-abc", "HTTPFailed", "pod/readiness/8080", "HTTP 503", 65)
	state.Add(finding)
	runner := &Runner{Baseline: baseline.Baseline{Path: "baseline.ini", Rules: []baseline.Rule{{
		ID: "known-api", Code: finding.Code, Namespace: "ns", Workload: "Deployment/api",
		Expires: "2099-12-31", Reason: "既知の保守作業",
	}}}}
	runner.correlateAndApplyBaseline(snapshot, state)
	values := state.BySeverity(model.Warning, false)
	if len(values) != 1 || !values[0].Acknowledged || values[0].Acknowledgement == nil || values[0].Acknowledgement.Workload != "Deployment/ns/api" {
		t.Fatalf("健康なownerを使ってworkload baselineを適用できない: %#v", values)
	}
	if len(state.RootCauses) != 1 || state.RootCauses[0].Cause.Code != finding.Code || state.RootCauses[0].Classification != "cause_candidate" {
		t.Fatalf("単発接続失敗を低確信度の原因候補として相関できない: %#v", state.RootCauses)
	}
}

func TestErrorOutputMasksSecretsAndTerminalControls(t *testing.T) {
	buffer := &bytes.Buffer{}
	printError(buffer, fmt.Errorf("authorization=Basic dXNlcjpwYXNz\x1b[31m"))
	got := buffer.String()
	if strings.Contains(got, "dXNlcjpwYXNz") || strings.Contains(got, "\x1b") || !strings.Contains(got, "<masked>") {
		t.Fatalf("stderrのマスクまたは端末制御文字除去が不正: %q", got)
	}
}

func TestNoMaskIsRejectedForNonTerminalOutput(t *testing.T) {
	cfg := config.Defaults()
	cfg.Mask = false
	if _, err := enforceInteractiveMaskPolicy(cfg, &bytes.Buffer{}); err == nil {
		t.Fatal("redirect可能な非TTY出力で--no-maskを黙って受理した")
	}
}

func TestResolveSelectedPodUsesFreshObject(t *testing.T) {
	selected := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-1")}, Status: corev1.PodStatus{Phase: corev1.PodPending}}
	fresh := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-1")}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}

	got, err := resolveSelectedPod([]corev1.Pod{fresh}, selected)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != corev1.PodRunning {
		t.Fatalf("選択時の古いPod状態を使用した: phase=%s", got.Status.Phase)
	}
	got.Status.Phase = corev1.PodFailed
	if fresh.Status.Phase != corev1.PodRunning {
		t.Fatal("返却Podがスナップショットを共有している")
	}
}

func TestResolveSelectedPodRejectsDeletedOrRecreatedTarget(t *testing.T) {
	selected := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-1")}}
	if _, err := resolveSelectedPod(nil, selected); err == nil {
		t.Fatal("削除済みPodを診断対象として受理した")
	}
	recreated := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-2")}}
	if _, err := resolveSelectedPod([]corev1.Pod{recreated}, selected); err == nil {
		t.Fatal("同名で再作成された別UIDのPodを診断対象として受理した")
	}
}

func TestReadyRatioIncludesNativeSidecar(t *testing.T) {
	restartAlways := corev1.ContainerRestartPolicyAlways
	pod := corev1.Pod{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "sidecar", RestartPolicy: &restartAlways}},
			Containers:     []corev1.Container{{Name: "app"}},
		},
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{{Name: "sidecar", Ready: false}},
			ContainerStatuses:     []corev1.ContainerStatus{{Name: "app", Ready: true}},
		},
	}
	ready, total := readyRatio(&pod)
	if ready != 1 || total != 2 {
		t.Fatalf("ready=%d/%d, want 1/2", ready, total)
	}
}

func TestLogSelectionIncludesRunningButUnhealthyPods(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	readyTrue := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	readyFalse := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	base := corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: readyTrue, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	cfg := config.Defaults()
	if !isHealthyPod(&base, cfg, now) {
		t.Fatal("ReadyなRunning Podを異常ログ対象にした")
	}
	notReady := base.DeepCopy()
	notReady.Status.Conditions = readyFalse
	if isHealthyPod(notReady, cfg, now) {
		t.Fatal("RunningだがReady=FalseのPodを健康扱いした")
	}
	restarted := base.DeepCopy()
	restarted.Status.ContainerStatuses[0].RestartCount = int32(cfg.RestartThreshold)
	restarted.Status.ContainerStatuses[0].LastTerminationState.Terminated = &corev1.ContainerStateTerminated{Reason: "Error", FinishedAt: metav1.NewTime(now.Add(-time.Hour))}
	if isHealthyPod(restarted, cfg, now) {
		t.Fatal("直近再起動が警告閾値に達したPodを健康扱いした")
	}
	ephemeralFailure := base.DeepCopy()
	ephemeralFailure.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "debug", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}}}}
	if !isHealthyPod(ephemeralFailure, cfg, now) {
		t.Fatal("debug用ephemeral containerの終了だけでPodを異常扱いした")
	}
}

func TestCollectedLogsAreIncludedInCoverage(t *testing.T) {
	cfg := config.Defaults()
	cfg.Mode = "select"
	runner := &Runner{
		Config:      cfg,
		Clients:     &kube.Clients{Kube: kubefake.NewSimpleClientset()},
		LogAnalyzer: mustLogAnalyzer(t, cfg.LogSignatureLines),
	}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	state := model.NewState()
	runner.collectLogs(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, state, true)
	ok, unavailable, total := state.CoverageCounts()
	if ok != 2 || unavailable != 0 || total != 2 {
		t.Fatalf("current/previousログのCoverage=%d/%d unavailable=%d", ok, total, unavailable)
	}
}

func TestUnusedDiagnosticsExposePartialAcquisitionAndCoverage(t *testing.T) {
	snapshot := kube.NewSnapshot()
	for _, key := range []string{"pods", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs", "ingresses", "configmaps", "secrets", "pvcs", "serviceaccounts"} {
		snapshot.Statuses[key] = kube.FetchStatus{Available: true, Status: kube.StatusOK}
	}
	snapshot.Statuses["deployments"] = kube.FetchStatus{Available: false, Status: kube.StatusForbidden, Reason: "RBAC Forbidden"}
	snapshot.ConfigMaps = []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "ns"}}}
	state := model.NewState()
	addUnusedDiagnostics(snapshot, state, false)

	ok, unavailable, total := state.CoverageCounts()
	if ok != 11 || unavailable != 1 || total != 12 {
		t.Fatalf("未使用診断Coverage=%d/%d unavailable=%d", ok, total, unavailable)
	}
	foundGap, foundCandidate := false, false
	for _, finding := range state.Findings {
		if finding.RuleID != "unused" {
			t.Fatalf("未使用診断のrule_idが不正: %#v", finding)
		}
		foundGap = foundGap || finding.Code == "K8S.UNUSED.PARTIAL_UNAVAILABLE"
		foundCandidate = foundCandidate || finding.Code == "K8S.UNUSED.CANDIDATE" && finding.Resource == "ConfigMap/ns/settings"
	}
	if !foundGap || !foundCandidate {
		t.Fatalf("部分取得または取得範囲内候補が欠落: %#v", state.Findings)
	}
}

func mustLogAnalyzer(t *testing.T, lines int) *rules.LogAnalyzer {
	t.Helper()
	analyzer, err := rules.NewLogAnalyzer("", lines)
	if err != nil {
		t.Fatal(err)
	}
	return analyzer
}

func TestListSummaryUsesPodPhaseNotDisplayReason(t *testing.T) {
	pod := corev1.Pod{Status: corev1.PodStatus{
		Phase:             corev1.PodPending,
		ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}}},
	}}
	counts := podPhaseCounts([]corev1.Pod{pod})
	if podStatus(&pod) != "ImagePullBackOff" || counts["Pending"] != 1 || counts["ImagePullBackOff"] != 0 {
		t.Fatalf("表示reasonをphase集計へ混入した: %#v", counts)
	}
}

func TestNewestBytesKeepsLogTailAndUTF8(t *testing.T) {
	value := "old\n" + string(make([]byte, 100)) + "\n直近のエラー"
	got := newestBytes(value, 30)
	if got == "" || got[len(got)-len("直近のエラー"):] != "直近のエラー" {
		t.Fatalf("最新ログが残っていない: %q", got)
	}
}

func TestNodeMetricRowsCalculateAllocatablePercentages(t *testing.T) {
	snapshot := &kube.Snapshot{
		Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("4Gi"),
		}}}},
		NodeMetrics: []unstructured.Unstructured{{Object: map[string]any{
			"metadata": map[string]any{"name": "node-a"},
			"usage":    map[string]any{"cpu": "1000m", "memory": "1Gi"},
		}}},
	}
	rows := nodeMetricRows(snapshot)
	if len(rows) != 1 || rows[0].Cells[2] != "50%" || rows[0].Cells[4] != "25%" {
		t.Fatalf("Node使用率が不正: %#v", rows)
	}
}

func TestMetricNotFoundIsReportedAsUnavailableAPI(t *testing.T) {
	got := fetchStatusText(kube.FetchStatus{Status: kube.StatusNotFound})
	if got != "API未提供 (NotFound)" {
		t.Fatalf("NotFoundをAPI到達不能と誤表示した: %q", got)
	}
}

func TestPodMetricRowsSortCPUAndLimitTen(t *testing.T) {
	items := make([]unstructured.Unstructured, 0, 11)
	for index := 1; index <= 11; index++ {
		items = append(items, unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"namespace": "ns", "name": fmt.Sprintf("pod-%02d", index)},
			"containers": []any{
				map[string]any{"usage": map[string]any{"cpu": fmt.Sprintf("%dm", index), "memory": "1Mi"}},
				map[string]any{"usage": map[string]any{"cpu": "1m", "memory": "2Mi"}},
			},
		}})
	}
	rows := podMetricRows(items, 10)
	if len(rows) != 10 || rows[0].Cells[1] != "pod-11" || rows[0].Cells[2] != "12m" || rows[0].Cells[3] != "3Mi" {
		t.Fatalf("Podメトリクスの集計・順序・上限が不正: %#v", rows)
	}
	for _, row := range rows {
		if row.Cells[1] == "pod-01" {
			t.Fatalf("CPU最下位Podが上位10件へ残った: %#v", rows)
		}
	}
}
