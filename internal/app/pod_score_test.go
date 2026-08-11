package app

import (
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCalculatePodScoreHealthyPodIsOneHundred(t *testing.T) {
	pod := scoredPod(corev1.PodRunning, corev1.ConditionTrue, corev1.ContainerStatus{
		Name: "app", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	})
	score := calculatePodScore(pod, model.NewState(), nil)
	if score.Score != 100 || score.Maximum != 100 {
		t.Fatalf("healthy Pod score=%d/%d, want 100/100: %#v", score.Score, score.Maximum, score.Dimensions)
	}
}

func TestCalculatePodScoreDoesNotPenalizeCompletedInitContainer(t *testing.T) {
	pod := scoredPod(corev1.PodRunning, corev1.ConditionTrue, corev1.ContainerStatus{
		Name: "app", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	})
	pod.Spec.InitContainers = []corev1.Container{{Name: "prepare"}}
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name: "prepare",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
			ExitCode: 0,
			Reason:   "Completed",
		}},
	}}

	score := calculatePodScore(pod, model.NewState(), nil)
	if score.Score != 100 {
		t.Fatalf("正常完了したinit containerで減点された: score=%d dimensions=%#v", score.Score, score.Dimensions)
	}
}

func TestCalculatePodScoreDoesNotDoubleCountCrashLoopFinding(t *testing.T) {
	pod := scoredPod(corev1.PodRunning, corev1.ConditionFalse, corev1.ContainerStatus{
		Name: "app", Ready: false,
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
	})
	state := model.NewState()
	state.Add(model.NewFinding(model.Issue, "K8S.POD.ABNORMAL_STATE", "コンテナ状態", "Pod/ns/api", "CrashLoopBackOff", "app", "failed", 100))

	score := calculatePodScore(pod, state, nil)
	restartLog := score.Dimensions[3]
	if restartLog.Score != 0 || restartLog.Detail != "実行異常 1件" {
		t.Fatalf("同じCrashLoopが二重計上された: %#v", restartLog)
	}
}

func TestCalculatePodScoreCrashLoopIsCritical(t *testing.T) {
	pod := scoredPod(corev1.PodRunning, corev1.ConditionFalse, corev1.ContainerStatus{
		Name: "app", Ready: false,
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
	})
	score := calculatePodScore(pod, model.NewState(), nil)
	if score.Score >= 60 {
		t.Fatalf("CrashLoop中のPodが重大判定にならない: score=%d dimensions=%#v", score.Score, score.Dimensions)
	}
	if score.Dimensions[0].Score != 15 || score.Dimensions[1].Score != 0 || score.Dimensions[2].Score != 0 || score.Dimensions[3].Score != 0 {
		t.Fatalf("ライフサイクル/Ready/コンテナ/再起動の配点が不正: %#v", score.Dimensions)
	}
}

func TestCalculatePodScoreIncludesDependencyAndProbeFindings(t *testing.T) {
	pod := scoredPod(corev1.PodRunning, corev1.ConditionTrue, corev1.ContainerStatus{
		Name: "app", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	})
	state := model.NewState()
	state.Add(model.NewFinding(model.Issue, "K8S.DEPENDENCY.MISSING_KEY", "関連リソース", "Secret/ns/config", "MissingKey", "password", "missing", 100))
	state.Add(model.NewFinding(model.Warning, "K8S.CONNECT.HTTP_FAILED", "接続確認", "Probe/ns/api/app/readinessProbe", "readinessProbe", "ready", "failed", 70))
	score := calculatePodScore(pod, state, nil)
	if score.Score != 90 { // 100 - dependency 7 - connect warning 3
		t.Fatalf("関連所見がPod総合スコアへ反映されない: score=%d dimensions=%#v", score.Score, score.Dimensions)
	}
}

func TestCalculatePodScoreIncludesTLSCertificateFailure(t *testing.T) {
	pod := scoredPod(corev1.PodRunning, corev1.ConditionTrue, corev1.ContainerStatus{
		Name: "app", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	})
	state := model.NewState()
	state.Add(model.NewFinding(model.Issue, "K8S.TLS.CERT_EXPIRED", "TLS", "Secret/ns/web-tls", "Expired", "cert", "expired", 100))
	score := calculatePodScore(pod, state, nil)
	if score.Score != 96 || score.Dimensions[len(score.Dimensions)-1].Score != 0 {
		t.Fatalf("TLS期限切れがIngress・TLS項目へ反映されない: score=%d dimensions=%#v", score.Score, score.Dimensions)
	}
}

func TestCalculatePodScoreUsesPodMetricsMemoryLimitRatio(t *testing.T) {
	pod := scoredPod(corev1.PodRunning, corev1.ConditionTrue, corev1.ContainerStatus{
		Name: "app", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	})
	pod.Spec.Containers[0].Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("100Mi")}
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["pod_metrics"] = kube.FetchStatus{Available: true}
	snapshot.PodMetrics = []unstructured.Unstructured{{Object: map[string]any{
		"metadata":   map[string]any{"namespace": "ns", "name": "api"},
		"containers": []any{map[string]any{"name": "app", "usage": map[string]any{"memory": "95Mi"}}},
	}}}
	score := calculatePodScore(pod, model.NewState(), snapshot)
	if score.Score != 97 || score.Dimensions[4].Score != 2 {
		t.Fatalf("memory limit比がResources項目へ反映されない: score=%d dimensions=%#v", score.Score, score.Dimensions)
	}
}

func scoredPod(phase corev1.PodPhase, ready corev1.ConditionStatus, status corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{
			Phase:             phase,
			Conditions:        []corev1.PodCondition{{Type: corev1.PodReady, Status: ready}},
			ContainerStatuses: []corev1.ContainerStatus{status},
		},
	}
}
