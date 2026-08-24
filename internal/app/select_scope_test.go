package app

import (
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func TestScopeSnapshotToSelectedPodExcludesUnrelatedResources(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-1", UID: types.UID("pod-1"), Labels: map[string]string{"app": "api"}},
		Spec: corev1.PodSpec{
			ServiceAccountName: "api-sa",
			Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{Name: "DEPENDENCY_URL", Value: "http://dependency/ready"}}, EnvFrom: []corev1.EnvFromSource{
				{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "api-config"}}},
				{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "api-secret"}}},
			}}},
			Volumes: []corev1.Volume{
				{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "api-data"}}},
				{Name: "csi", VolumeSource: corev1.VolumeSource{CSI: &corev1.CSIVolumeSource{Driver: "example.test", NodePublishSecretRef: &corev1.LocalObjectReference{Name: "csi-secret"}}}},
			},
		},
		Status: corev1.PodStatus{PodIP: "10.0.0.8"},
	}
	snapshot := kube.NewSnapshot()
	snapshot.Pods = []corev1.Pod{pod, {ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker", Labels: map[string]string{"app": "worker"}}}}
	snapshot.Services = []corev1.Service{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "dependency"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "worker"}}},
	}
	snapshot.EndpointSlices = []discoveryv1.EndpointSlice{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-a", Labels: map[string]string{discoveryv1.LabelServiceName: "api"}}, Endpoints: []discoveryv1.Endpoint{{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "ns", Name: "api-1", UID: types.UID("pod-1")}}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker-a", Labels: map[string]string{discoveryv1.LabelServiceName: "worker"}}},
	}
	apiIngress := ingressForService("ns", "api-ingress", "api")
	apiIngress.Spec.TLS = []networkingv1.IngressTLS{{SecretName: "api-tls"}}
	snapshot.Ingresses = []networkingv1.Ingress{apiIngress, ingressForService("ns", "worker-ingress", "worker")}
	snapshot.ConfigMaps = []corev1.ConfigMap{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-config"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker-config"}},
	}
	snapshot.Secrets = []kube.SecretProjection{
		{Namespace: "ns", Name: "api-secret"}, {Namespace: "ns", Name: "api-tls", Type: corev1.SecretTypeTLS},
		{Namespace: "ns", Name: "csi-secret"}, {Namespace: "ns", Name: "worker-secret"},
	}
	snapshot.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-sa"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker-sa"}},
	}
	snapshot.NetworkPolicies = []networkingv1.NetworkPolicy{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-policy"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker-policy"}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "worker"}}}},
	}
	snapshot.PodMetrics = []unstructured.Unstructured{
		{Object: map[string]any{"metadata": map[string]any{"namespace": "ns", "name": "api-1"}}},
		{Object: map[string]any{"metadata": map[string]any{"namespace": "ns", "name": "worker"}}},
	}
	snapshot.PersistentVolumeClaims = []corev1.PersistentVolumeClaim{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-data"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker-data"}},
	}
	snapshot.Events = []corev1.Event{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-event"}, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "ns", Name: "api-1", UID: types.UID("pod-1")}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "worker-event"}, InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "ns", Name: "worker"}},
	}

	scoped := scopeSnapshotToSelectedPod(snapshot, &pod)
	if len(scoped.Pods) != 1 || scoped.Pods[0].Name != "api-1" {
		t.Fatalf("選択Pod以外が残った: %#v", scoped.Pods)
	}
	if len(scoped.Services) != 2 || scoped.Services[0].Name != "api" || scoped.Services[1].Name != "dependency" {
		t.Fatalf("無関係なServiceが残った: %#v", scoped.Services)
	}
	if len(scoped.EndpointSlices) != 1 || scoped.EndpointSlices[0].Name != "api-a" {
		t.Fatalf("無関係なEndpointSliceが残った: %#v", scoped.EndpointSlices)
	}
	if len(scoped.Ingresses) != 1 || scoped.Ingresses[0].Name != "api-ingress" {
		t.Fatalf("無関係なIngressが残った: %#v", scoped.Ingresses)
	}
	if len(scoped.PersistentVolumeClaims) != 1 || scoped.PersistentVolumeClaims[0].Name != "api-data" {
		t.Fatalf("無関係なPVCが残った: %#v", scoped.PersistentVolumeClaims)
	}
	if len(scoped.ConfigMaps) != 1 || scoped.ConfigMaps[0].Name != "api-config" {
		t.Fatalf("無関係なConfigMapが残った: %#v", scoped.ConfigMaps)
	}
	if len(scoped.Secrets) != 3 || scoped.Secrets[0].Name != "api-secret" || scoped.Secrets[1].Name != "api-tls" || scoped.Secrets[2].Name != "csi-secret" {
		t.Fatalf("参照Secretの絞り込みが不正: %#v", scoped.Secrets)
	}
	if len(scoped.ServiceAccounts) != 1 || scoped.ServiceAccounts[0].Name != "api-sa" {
		t.Fatalf("無関係なServiceAccountが残った: %#v", scoped.ServiceAccounts)
	}
	if len(scoped.NetworkPolicies) != 1 || scoped.NetworkPolicies[0].Name != "api-policy" {
		t.Fatalf("無関係なNetworkPolicyが残った: %#v", scoped.NetworkPolicies)
	}
	if len(scoped.PodMetrics) != 1 || scoped.PodMetrics[0].GetName() != "api-1" {
		t.Fatalf("無関係なPod metricsが残った: %#v", scoped.PodMetrics)
	}
	if len(scoped.Events) != 1 || scoped.Events[0].Name != "api-event" {
		t.Fatalf("無関係なEventが残った: %#v", scoped.Events)
	}
}

func TestScopeSnapshotRetainsExternalNameTarget(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "ns"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "client", Env: []corev1.EnvVar{{Name: "TARGET_URL", Value: "http://alias/data"}}}}}}
	snapshot := kube.NewSnapshot()
	snapshot.Pods = []corev1.Pod{pod}
	snapshot.Services = []corev1.Service{
		{ObjectMeta: metav1.ObjectMeta{Name: "alias", Namespace: "ns"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: "backend.ns.svc.cluster.local"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "ns"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "ns"}},
	}
	scoped := scopeSnapshotToSelectedPod(snapshot, &pod)
	if len(scoped.Services) != 2 || scoped.Services[0].Name != "alias" || scoped.Services[1].Name != "backend" {
		t.Fatalf("ExternalNameまたは参照先Serviceの絞り込みが不正: %#v", scoped.Services)
	}
}

func ingressForService(namespace, name, service string) networkingv1.Ingress {
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       networkingv1.IngressSpec{DefaultBackend: &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: service}}},
	}
}
