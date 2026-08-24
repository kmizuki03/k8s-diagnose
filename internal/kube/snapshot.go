//lint:file-ignore SA1019 EndpointSlice is primary, but legacy Endpoints remains an intentional compatibility fallback.

package kube

import (
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	nodev1 "k8s.io/api/node/v1"
	policyv1 "k8s.io/api/policy/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"time"
)

type SecretProjection struct {
	Namespace       string
	Name            string
	Type            corev1.SecretType
	Keys            map[string]struct{}
	TLSCert         []byte
	TLSKeyPairError string
}

type FetchStatus struct {
	Available bool
	Status    ErrorStatus
	Reason    string
	HTTPCode  int32
}

type Snapshot struct {
	// ScopeNamespace is empty for a cluster-wide collection and contains the
	// requested namespace otherwise. Rules use it to avoid declaring a
	// cross-namespace reference missing when that namespace was never listed.
	ScopeNamespace         string
	Pods                   []corev1.Pod
	AllPods                []corev1.Pod
	Nodes                  []corev1.Node
	NodeLeases             []coordinationv1.Lease
	Services               []corev1.Service
	Endpoints              []corev1.Endpoints
	EndpointSlices         []discoveryv1.EndpointSlice
	PersistentVolumeClaims []corev1.PersistentVolumeClaim
	PersistentVolumes      []corev1.PersistentVolume
	ConfigMaps             []corev1.ConfigMap
	Secrets                []SecretProjection
	ServiceAccounts        []corev1.ServiceAccount
	Namespaces             []corev1.Namespace
	Events                 []corev1.Event
	ResourceQuotas         []corev1.ResourceQuota
	LimitRanges            []corev1.LimitRange
	Deployments            []appsv1.Deployment
	StatefulSets           []appsv1.StatefulSet
	DaemonSets             []appsv1.DaemonSet
	ReplicaSets            []appsv1.ReplicaSet
	Jobs                   []batchv1.Job
	CronJobs               []batchv1.CronJob
	HPAs                   []autoscalingv2.HorizontalPodAutoscaler
	Ingresses              []networkingv1.Ingress
	IngressClasses         []networkingv1.IngressClass
	NetworkPolicies        []networkingv1.NetworkPolicy
	ValidatingWebhooks     []admissionv1.ValidatingWebhookConfiguration
	MutatingWebhooks       []admissionv1.MutatingWebhookConfiguration
	StorageClasses         []storagev1.StorageClass
	PodDisruptionBudgets   []policyv1.PodDisruptionBudget
	PriorityClasses        []schedulingv1.PriorityClass
	RuntimeClasses         []nodev1.RuntimeClass
	NodeMetrics            []unstructured.Unstructured
	PodMetrics             []unstructured.Unstructured
	APIServices            []unstructured.Unstructured
	CustomResourceDefs     []unstructured.Unstructured
	GatewayClasses         []unstructured.Unstructured
	Gateways               []unstructured.Unstructured
	HTTPRoutes             []unstructured.Unstructured
	Readyz                 string
	Livez                  string
	APIWarnings            []string
	ServerTime             time.Time
	Statuses               map[string]FetchStatus

	// indexed caches the namespace/name lookup maps. It is unexported so it is
	// never serialised, and must be dropped via ResetIndex whenever one of the
	// indexed collections is replaced.
	indexed *snapshotIndex
}

func NewSnapshot() *Snapshot { return &Snapshot{Statuses: map[string]FetchStatus{}} }

func (s *Snapshot) Available(key string) bool {
	status, ok := s.Statuses[key]
	return ok && status.Available
}

// AvailableOrUntracked treats hand-built snapshots as available while keeping
// Collector-backed acquisition failures explicit.
func (s *Snapshot) AvailableOrUntracked(key string) bool {
	status, tracked := s.Statuses[key]
	return !tracked || status.Available
}

func (s *Snapshot) Status(key string) FetchStatus { return s.Statuses[key] }

// Lookups below are served from a lazily built name index. Rules resolve the
// same objects by namespace+name once per Pod (and, for scheduling, once per
// Pod x Node), so a linear scan per lookup made the rule set quadratic in
// cluster size.
//
// A Snapshot is filled during collection and only read afterwards, and rules
// run sequentially, so the lazy build needs no locking. Deliberately no
// sync.Once: Snapshot is shallow-copied by value when narrowing to a selected
// Pod, and copying a lock would trip go vet's copylocks check.
//
// Any code that replaces one of the indexed slices on a copied Snapshot MUST
// call ResetIndex, or lookups would still answer from the original's contents.
// TestScopedSnapshotDoesNotServeStaleIndex locks that behaviour in.

type snapshotIndex struct {
	secrets         map[string]*SecretProjection
	configMaps      map[string]*corev1.ConfigMap
	pvcs            map[string]*corev1.PersistentVolumeClaim
	pvs             map[string]*corev1.PersistentVolume
	serviceAccounts map[string]*corev1.ServiceAccount
	priorityClasses map[string]*schedulingv1.PriorityClass
	runtimeClasses  map[string]*nodev1.RuntimeClass
	storageClasses  map[string]*storagev1.StorageClass
}

func namespacedKey(namespace, name string) string { return namespace + "/" + name }

// ResetIndex discards the cached name index. Call it after replacing any of the
// indexed collections on a Snapshot, in particular on a shallow copy.
func (s *Snapshot) ResetIndex() { s.indexed = nil }

func (s *Snapshot) index() *snapshotIndex {
	if s.indexed == nil {
		index := &snapshotIndex{
			secrets:         make(map[string]*SecretProjection, len(s.Secrets)),
			configMaps:      make(map[string]*corev1.ConfigMap, len(s.ConfigMaps)),
			pvcs:            make(map[string]*corev1.PersistentVolumeClaim, len(s.PersistentVolumeClaims)),
			pvs:             make(map[string]*corev1.PersistentVolume, len(s.PersistentVolumes)),
			serviceAccounts: make(map[string]*corev1.ServiceAccount, len(s.ServiceAccounts)),
			priorityClasses: make(map[string]*schedulingv1.PriorityClass, len(s.PriorityClasses)),
			runtimeClasses:  make(map[string]*nodev1.RuntimeClass, len(s.RuntimeClasses)),
			storageClasses:  make(map[string]*storagev1.StorageClass, len(s.StorageClasses)),
		}
		// First writer wins throughout, matching the linear scans these maps
		// replace: they returned the first match.
		for i := range s.Secrets {
			key := namespacedKey(s.Secrets[i].Namespace, s.Secrets[i].Name)
			if _, exists := index.secrets[key]; !exists {
				index.secrets[key] = &s.Secrets[i]
			}
		}
		for i := range s.ConfigMaps {
			key := namespacedKey(s.ConfigMaps[i].Namespace, s.ConfigMaps[i].Name)
			if _, exists := index.configMaps[key]; !exists {
				index.configMaps[key] = &s.ConfigMaps[i]
			}
		}
		for i := range s.PersistentVolumeClaims {
			key := namespacedKey(s.PersistentVolumeClaims[i].Namespace, s.PersistentVolumeClaims[i].Name)
			if _, exists := index.pvcs[key]; !exists {
				index.pvcs[key] = &s.PersistentVolumeClaims[i]
			}
		}
		for i := range s.PersistentVolumes {
			if _, exists := index.pvs[s.PersistentVolumes[i].Name]; !exists {
				index.pvs[s.PersistentVolumes[i].Name] = &s.PersistentVolumes[i]
			}
		}
		for i := range s.ServiceAccounts {
			key := namespacedKey(s.ServiceAccounts[i].Namespace, s.ServiceAccounts[i].Name)
			if _, exists := index.serviceAccounts[key]; !exists {
				index.serviceAccounts[key] = &s.ServiceAccounts[i]
			}
		}
		for i := range s.PriorityClasses {
			if _, exists := index.priorityClasses[s.PriorityClasses[i].Name]; !exists {
				index.priorityClasses[s.PriorityClasses[i].Name] = &s.PriorityClasses[i]
			}
		}
		for i := range s.RuntimeClasses {
			if _, exists := index.runtimeClasses[s.RuntimeClasses[i].Name]; !exists {
				index.runtimeClasses[s.RuntimeClasses[i].Name] = &s.RuntimeClasses[i]
			}
		}
		for i := range s.StorageClasses {
			if _, exists := index.storageClasses[s.StorageClasses[i].Name]; !exists {
				index.storageClasses[s.StorageClasses[i].Name] = &s.StorageClasses[i]
			}
		}
		s.indexed = index
	}
	return s.indexed
}

func (s *Snapshot) Secret(namespace, name string) (SecretProjection, bool) {
	if value, ok := s.index().secrets[namespacedKey(namespace, name)]; ok {
		return *value, true
	}
	return SecretProjection{}, false
}

func (s *Snapshot) ConfigMap(namespace, name string) (corev1.ConfigMap, bool) {
	if value, ok := s.index().configMaps[namespacedKey(namespace, name)]; ok {
		return *value, true
	}
	return corev1.ConfigMap{}, false
}

// PersistentVolumeClaim returns the claim by namespace and name.
func (s *Snapshot) PersistentVolumeClaim(namespace, name string) (*corev1.PersistentVolumeClaim, bool) {
	value, ok := s.index().pvcs[namespacedKey(namespace, name)]
	return value, ok
}

// PersistentVolume returns the cluster-scoped volume by name.
func (s *Snapshot) PersistentVolume(name string) (*corev1.PersistentVolume, bool) {
	value, ok := s.index().pvs[name]
	return value, ok
}

// ServiceAccount returns the account by namespace and name.
func (s *Snapshot) ServiceAccount(namespace, name string) (*corev1.ServiceAccount, bool) {
	value, ok := s.index().serviceAccounts[namespacedKey(namespace, name)]
	return value, ok
}

// PriorityClass returns the cluster-scoped priority class by name.
func (s *Snapshot) PriorityClass(name string) (*schedulingv1.PriorityClass, bool) {
	value, ok := s.index().priorityClasses[name]
	return value, ok
}

// RuntimeClass returns the cluster-scoped runtime class by name.
func (s *Snapshot) RuntimeClass(name string) (*nodev1.RuntimeClass, bool) {
	value, ok := s.index().runtimeClasses[name]
	return value, ok
}

// StorageClass returns the cluster-scoped storage class by name.
func (s *Snapshot) StorageClass(name string) (*storagev1.StorageClass, bool) {
	value, ok := s.index().storageClasses[name]
	return value, ok
}
