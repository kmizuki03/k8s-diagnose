package rules

import (
	"context"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestServiceRuleUsesAllPodsForSelectedPodDependency(t *testing.T) {
	client := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "client", Labels: map[string]string{"app": "client"}}}
	backend := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-1", Labels: map[string]string{"app": "api"}}}
	snapshot := kube.NewSnapshot()
	snapshot.Pods = []corev1.Pod{client}
	snapshot.AllPods = []corev1.Pod{client, backend}
	snapshot.Services = []corev1.Service{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "api"}},
	}}

	findings := (ServiceRule{}).Evaluate(context.Background(), snapshot, config.Config{})
	if hasFindingCode(findings, "K8S.SERVICE.SELECTOR_NO_MATCH") {
		t.Fatalf("個別診断で依存Serviceの正常なbackend Podを見失った: %#v", findings)
	}
}
