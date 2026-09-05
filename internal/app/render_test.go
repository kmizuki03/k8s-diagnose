package app

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestPodStatusShowsReadinessFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		ready     bool
		condition corev1.ConditionStatus
		waiting   string
		want      string
	}{
		{name: "ready", ready: true, condition: corev1.ConditionTrue, want: "Running"},
		{name: "container not ready", want: "NotReady"},
		{name: "readiness gate", ready: true, condition: corev1.ConditionFalse, want: "NotReady"},
		{name: "unknown readiness", ready: true, condition: corev1.ConditionUnknown, want: "NotReady"},
		{name: "waiting reason retained", waiting: "CrashLoopBackOff", want: "CrashLoopBackOff"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pod := corev1.Pod{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "api"}}},
				Status: corev1.PodStatus{Phase: corev1.PodRunning,
					ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Ready: test.ready}},
				},
			}
			if test.condition != "" {
				pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: test.condition}}
			}
			if test.waiting != "" {
				pod.Status.ContainerStatuses[0].State.Waiting = &corev1.ContainerStateWaiting{Reason: test.waiting}
			}
			if got := podStatus(&pod); got != test.want {
				t.Fatalf("STATUS=%q, want %q", got, test.want)
			}
			row := podRows([]corev1.Pod{pod})[0]
			if row.Status != test.want || row.Cells[3] != test.want {
				t.Fatalf("表と色分けの状態が一致しない: %#v", row)
			}
		})
	}
}

func TestAgeTextUnknownAndFuture(t *testing.T) {
	if got := ageText(time.Time{}); got != "<unknown>" {
		t.Fatalf("取得できない日時が経過日数になった: %q", got)
	}
	if got := ageText(time.Now().Add(time.Hour)); got != "0s" {
		t.Fatalf("未来の日時が負になった: %q", got)
	}
}
