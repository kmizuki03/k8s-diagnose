package rules

import (
	"context"
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

// buildScaleSnapshot synthesises a cluster shaped like a real one: pods spread
// across namespaces, each owned by a ReplicaSet and fronted by a Service that
// selects them by label, with a matching EndpointSlice. It is the fixture for
// measuring how Registry.Run scales — the "measure before optimising" gate for
// the O(n^k) concern raised in review.
//
// Measured on an Apple M4 Pro:
//
//	  500 pods:  ~4.1 ms
//	 1500 pods: ~11.6 ms
//	 3000 pods: ~22.3 ms
//	12000 pods: ~115 ms   (full registry, scaling check)
//
// Scaling is now effectively linear (2x input -> ~2x time). It was not before:
// Service-to-Pod selector matching rebuilt a labels.Selector for every
// (Service, Pod) pair and rescanned every Pod in the cluster per Service, which
// measured quadratic — 2x input -> ~4x time, reaching 143 ms for the Service
// rule alone at 12k pods. That is fixed by podsByNamespace (one selector per
// Service, candidates limited to its namespace) and by the name index on
// kube.Snapshot backing the Secret/ConfigMap/PVC/PV/ServiceAccount/
// PriorityClass/RuntimeClass/StorageClass lookups.
//
// Keep the fixture representative: it must contain the objects the rules
// actually resolve. Dropping the ConfigMaps/Secrets/ServiceAccounts, the Nodes,
// or the pending Pods makes the corresponding rules short-circuit, and the
// benchmark then measures nothing while appearing healthy.
func buildScaleSnapshot(pods int) *kube.Snapshot {
	const (
		namespaces = 30
		podsPerApp = 10
	)
	apps := pods / podsPerApp
	if apps == 0 {
		apps = 1
	}
	snapshot := kube.NewSnapshot()

	ns := func(app int) string { return fmt.Sprintf("ns-%02d", app%namespaces) }
	protoTCP := corev1.ProtocolTCP

	snapshot.Pods = make([]corev1.Pod, 0, pods)
	for i := 0; i < pods; i++ {
		app := i % apps
		rs := fmt.Sprintf("app-%03d-rs", app)
		snapshot.Pods = append(snapshot.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("app-%03d-pod-%05d", app, i),
				Namespace: ns(app),
				UID:       types.UID(fmt.Sprintf("pod-%05d", i)),
				Labels:    map[string]string{"app": fmt.Sprintf("app-%03d", app)},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs, Controller: boolPtr(true),
				}},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "main",
					Image: "example/app:1.0",
					Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080, Protocol: protoTCP}},
				}},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name: "main", Ready: true, RestartCount: 0, Started: boolPtr(true),
					State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
				}},
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		})
	}
	snapshot.AllPods = append([]corev1.Pod{}, snapshot.Pods...)

	snapshot.Services = make([]corev1.Service, 0, apps)
	snapshot.EndpointSlices = make([]discoveryv1.EndpointSlice, 0, apps)
	snapshot.ReplicaSets = make([]appsv1.ReplicaSet, 0, apps)
	snapshot.Deployments = make([]appsv1.Deployment, 0, apps)
	ready := true
	for app := 0; app < apps; app++ {
		name := fmt.Sprintf("app-%03d", app)
		namespace := ns(app)
		snapshot.Services = append(snapshot.Services, corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: corev1.ServiceSpec{
				Type:     corev1.ServiceTypeClusterIP,
				Selector: map[string]string{"app": name},
				Ports:    []corev1.ServicePort{{Name: "http", Port: 80, Protocol: protoTCP, TargetPort: intstr.FromString("http")}},
			},
		})
		port := int32(8080)
		snapshot.EndpointSlices = append(snapshot.EndpointSlices, discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name + "-abcde",
				Namespace: namespace,
				Labels:    map[string]string{discoveryv1.LabelServiceName: name},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			}},
			Ports: []discoveryv1.EndpointPort{{Name: strPtr("http"), Port: &port, Protocol: &protoTCP}},
		})
		snapshot.ReplicaSets = append(snapshot.ReplicaSets, appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name: name + "-rs", Namespace: namespace,
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: name, Controller: boolPtr(true)}},
			},
			Spec:   appsv1.ReplicaSetSpec{Replicas: int32Pointer(podsPerApp)},
			Status: appsv1.ReplicaSetStatus{Replicas: podsPerApp, ReadyReplicas: podsPerApp, AvailableReplicas: podsPerApp},
		})
		snapshot.Deployments = append(snapshot.Deployments, appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec:       appsv1.DeploymentSpec{Replicas: int32Pointer(podsPerApp)},
			Status:     appsv1.DeploymentStatus{Replicas: podsPerApp, ReadyReplicas: podsPerApp, AvailableReplicas: podsPerApp, UpdatedReplicas: podsPerApp},
		})
	}

	// Each app owns a ConfigMap, Secret and ServiceAccount, and every pod
	// references them. This is what exercises the dependency-resolution
	// lookups; without these objects the dependency rule short-circuits and the
	// benchmark measures nothing.
	snapshot.ConfigMaps = make([]corev1.ConfigMap, 0, apps)
	snapshot.Secrets = make([]kube.SecretProjection, 0, apps)
	snapshot.ServiceAccounts = make([]corev1.ServiceAccount, 0, apps)
	for app := 0; app < apps; app++ {
		name := fmt.Sprintf("app-%03d", app)
		namespace := ns(app)
		snapshot.ConfigMaps = append(snapshot.ConfigMaps, corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name + "-config", Namespace: namespace},
			Data:       map[string]string{"app.conf": "level=info"},
		})
		snapshot.Secrets = append(snapshot.Secrets, kube.SecretProjection{
			Namespace: namespace, Name: name + "-secret",
			Keys: map[string]struct{}{"token": {}},
		})
		snapshot.ServiceAccounts = append(snapshot.ServiceAccounts, corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: name + "-sa", Namespace: namespace},
		})
	}
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		app := fmt.Sprintf("app-%03d", i%apps)
		pod.Spec.ServiceAccountName = app + "-sa"
		pod.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{
			{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: app + "-config"}}},
			{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: app + "-secret"}}},
		}
	}

	// Nodes, storage and namespaced policy objects are what drive the
	// scheduling / dependency / lifecycle rules. Without them the benchmark
	// silently skips the very paths most at risk of super-linear behaviour.
	nodes := pods / 30
	if nodes < 3 {
		nodes = 3
	}
	snapshot.Nodes = make([]corev1.Node, 0, nodes)
	for i := 0; i < nodes; i++ {
		snapshot.Nodes = append(snapshot.Nodes, corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   fmt.Sprintf("node-%03d", i),
				Labels: map[string]string{corev1.LabelHostname: fmt.Sprintf("node-%03d", i)},
			},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
					corev1.ResourcePods:   resource.MustParse("110"),
				},
			},
		})
	}

	snapshot.StorageClasses = []storagev1.StorageClass{
		{ObjectMeta: metav1.ObjectMeta{Name: "standard"}, Provisioner: "example.com/pd"},
		{ObjectMeta: metav1.ObjectMeta{Name: "fast"}, Provisioner: "example.com/ssd"},
	}
	standard := "standard"
	snapshot.PersistentVolumeClaims = make([]corev1.PersistentVolumeClaim, 0, apps)
	snapshot.PersistentVolumes = make([]corev1.PersistentVolume, 0, apps)
	for app := 0; app < apps; app++ {
		name := fmt.Sprintf("app-%03d", app)
		volume := name + "-pv"
		snapshot.PersistentVolumeClaims = append(snapshot.PersistentVolumeClaims, corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: name + "-data", Namespace: ns(app)},
			Spec:       corev1.PersistentVolumeClaimSpec{StorageClassName: &standard, VolumeName: volume},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		})
		snapshot.PersistentVolumes = append(snapshot.PersistentVolumes, corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: volume},
			Spec:       corev1.PersistentVolumeSpec{StorageClassName: standard},
			Status:     corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound},
		})
	}

	// Pending pods that reference a PVC are the input to the scheduling rule,
	// which assesses every pending pod against every node.
	for app := 0; app < apps && app < 50; app++ {
		name := fmt.Sprintf("app-%03d", app)
		snapshot.Pods = append(snapshot.Pods, corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: name + "-pending", Namespace: ns(app),
				UID:    types.UID(name + "-pending"),
				Labels: map[string]string{"app": name},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name: "main", Image: "example/app:1.0",
					Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("512Mi"),
					}},
				}},
				Volumes: []corev1.Volume{{
					Name: "data",
					VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: name + "-data",
					}},
				}},
			},
			Status: corev1.PodStatus{Phase: corev1.PodPending},
		})
	}
	snapshot.AllPods = append([]corev1.Pod{}, snapshot.Pods...)

	snapshot.LimitRanges = make([]corev1.LimitRange, 0, namespaces)
	snapshot.NetworkPolicies = make([]networkingv1.NetworkPolicy, 0, namespaces)
	for i := 0; i < namespaces; i++ {
		namespace := fmt.Sprintf("ns-%02d", i)
		snapshot.LimitRanges = append(snapshot.LimitRanges, corev1.LimitRange{
			ObjectMeta: metav1.ObjectMeta{Name: "limits", Namespace: namespace},
			Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
				Type:           corev1.LimitTypeContainer,
				DefaultRequest: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")},
			}}},
		})
		snapshot.NetworkPolicies = append(snapshot.NetworkPolicies, networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "default-deny", Namespace: namespace},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			},
		})
		snapshot.Namespaces = append(snapshot.Namespaces, corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespace},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		})
	}

	for key := range Builtins().RequiredKeys("all") {
		snapshot.Statuses[key] = kube.FetchStatus{Available: true}
	}
	return snapshot
}

func benchmarkRegistryRun(b *testing.B, pods int) {
	registry := Builtins()
	cfg := config.Defaults()
	cfg.Mode = "all"
	snapshot := buildScaleSnapshot(pods)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := model.NewState()
		registry.Run(context.Background(), snapshot, cfg, state)
	}
}

func boolPtr(v bool) *bool    { return &v }
func strPtr(v string) *string { return &v }

func BenchmarkRegistryRun500(b *testing.B)  { benchmarkRegistryRun(b, 500) }
func BenchmarkRegistryRun1500(b *testing.B) { benchmarkRegistryRun(b, 1500) }
func BenchmarkRegistryRun3000(b *testing.B) { benchmarkRegistryRun(b, 3000) }
