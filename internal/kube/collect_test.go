package kube

import (
	"context"
	"errors"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestClusterWidePodCollectionSharesFailureWithAllPods(t *testing.T) {
	client := kubefake.NewSimpleClientset()
	client.Fake.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("denied"))
	})
	cfg := config.Defaults()
	snapshot := (&Collector{
		Clients: &Clients{Kube: client}, Config: cfg,
		Only: map[string]bool{"pods": true, "all_pods": true},
	}).Collect(context.Background())
	if snapshot.Status("pods").Available || snapshot.Status("all_pods").Available {
		t.Fatalf("共有したPod取得失敗がall_podsで成功扱いになった: %#v", snapshot.Statuses)
	}
	if len(client.Actions()) != 1 {
		t.Fatalf("cluster-wide Pod APIを重複取得した: %d actions", len(client.Actions()))
	}
}

func TestAllPodsCanBeCollectedWithoutScopedPods(t *testing.T) {
	client := kubefake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api"}})
	cfg := config.Defaults()
	snapshot := (&Collector{
		Clients: &Clients{Kube: client}, Config: cfg,
		Only: map[string]bool{"all_pods": true},
	}).Collect(context.Background())
	if !snapshot.Status("all_pods").Available || len(snapshot.AllPods) != 1 || len(snapshot.Pods) != 0 {
		t.Fatalf("all_pods単独収集が不正: statuses=%#v pods=%d all=%d", snapshot.Statuses, len(snapshot.Pods), len(snapshot.AllPods))
	}
}
