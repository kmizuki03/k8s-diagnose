package kube

import (
	"context"
	"errors"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
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

// An extension API is usually served under several versions at once, and which
// ones a cluster serves depends on how old its CRDs are. Asking for one version
// only means a cluster that has the resources but not that version answers
// NotFound, which the optional path reports as "there are none" — the resources
// look absent rather than unread, and every rule built on them goes quiet.
func TestOptionalDynamicListFallsBackToAServedVersion(t *testing.T) {
	v1 := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	beta := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "gateways"}
	object := unstructured.Unstructured{}
	object.SetAPIVersion("gateway.networking.k8s.io/v1beta1")
	object.SetKind("Gateway")
	object.SetNamespace("gw")
	object.SetName("web-gw")
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{v1: "GatewayList", beta: "GatewayList"})
	// The cluster serves only v1beta1, so v1 answers NotFound exactly as an
	// apiserver without that version would.
	client.Fake.PrependReactor("list", "gateways", func(action ktesting.Action) (bool, runtime.Object, error) {
		if action.GetResource().Version == "v1" {
			return true, nil, apierrors.NewNotFound(action.GetResource().GroupResource(), "")
		}
		list := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{object}}
		list.SetAPIVersion("gateway.networking.k8s.io/v1beta1")
		list.SetKind("GatewayList")
		return true, list, nil
	})
	collector := &Collector{Clients: &Clients{Dynamic: client}, Config: config.Defaults()}

	values, err := collector.listOptionalDynamicVersions(context.Background(),
		"gateway.networking.k8s.io", "gateways", "gw", "v1", "v1beta1")
	if err != nil {
		t.Fatalf("提供されているバージョンへ切り替えられない: %v", err)
	}
	if len(values) != 1 || values[0].GetName() != "web-gw" {
		t.Fatalf("v1beta1のGatewayを取得できない: %#v", values)
	}
}

// A cluster that does not use the API at all must stay silent rather than
// reporting a diagnosis failure.
func TestOptionalDynamicListStaysSilentWhenNoVersionIsServed(t *testing.T) {
	v1 := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
	beta := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1beta1", Resource: "gateways"}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{v1: "GatewayList", beta: "GatewayList"})
	client.Fake.PrependReactor("list", "gateways", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(action.GetResource().GroupResource(), "")
	})
	collector := &Collector{Clients: &Clients{Dynamic: client}, Config: config.Defaults()}
	values, err := collector.listOptionalDynamicVersions(context.Background(),
		"gateway.networking.k8s.io", "gateways", "gw", "v1", "v1beta1")
	if err != nil || len(values) != 0 {
		t.Fatalf("未導入のAPIで失敗扱いになった: values=%#v err=%v", values, err)
	}
}
