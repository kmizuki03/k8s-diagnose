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
	Readyz                 string
	Livez                  string
	APIWarnings            []string
	ServerTime             time.Time
	Statuses               map[string]FetchStatus
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

func (s *Snapshot) Secret(namespace, name string) (SecretProjection, bool) {
	for _, secret := range s.Secrets {
		if secret.Namespace == namespace && secret.Name == name {
			return secret, true
		}
	}
	return SecretProjection{}, false
}

func (s *Snapshot) ConfigMap(namespace, name string) (corev1.ConfigMap, bool) {
	for _, item := range s.ConfigMaps {
		if item.Namespace == namespace && item.Name == name {
			return item, true
		}
	}
	return corev1.ConfigMap{}, false
}
