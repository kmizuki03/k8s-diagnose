package rules

import (
	"reflect"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBaselineWorkloadResolverUsesOutermostCronJob(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nightly-123-pod", OwnerReferences: []metav1.OwnerReference{{Kind: "Job", Name: "nightly-123"}}}}
	job := batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nightly-123", OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "nightly"}}}}
	resolve := BaselineWorkloadResolver(&kube.Snapshot{Pods: []corev1.Pod{pod}, Jobs: []batchv1.Job{job}})
	got := resolve(model.Finding{Resource: "Pod/ns/nightly-123-pod"})
	want := []string{"CronJob/ns/nightly"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("生成Jobではなく最外側CronJobを返す必要がある: got=%v want=%v", got, want)
	}
}

func TestBaselineWorkloadResolverKeepsEverySharedDependencyConsumer(t *testing.T) {
	secretName := "shared"
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-a", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-rs"}}}, Spec: podSpecUsingSecret(secretName)},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker-a", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "worker-rs"}}}, Spec: podSpecUsingSecret(secretName)},
	}
	replicaSets := []appsv1.ReplicaSet{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-rs", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api"}}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker-rs", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "worker"}}}},
	}
	resolve := BaselineWorkloadResolver(&kube.Snapshot{Pods: pods, ReplicaSets: replicaSets})
	got := resolve(model.Finding{Resource: "Secret/ns/shared"})
	want := []string{"Deployment/ns/api", "Deployment/ns/worker"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("共有依存先の全consumerを保持する必要がある: got=%v want=%v", got, want)
	}
}

func podSpecUsingSecret(name string) corev1.PodSpec {
	return corev1.PodSpec{Containers: []corev1.Container{{
		Name:    "app",
		EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: name}}}},
	}}}
}
