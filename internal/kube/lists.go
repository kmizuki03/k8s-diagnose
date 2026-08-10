//lint:file-ignore SA1019 EndpointSlice is primary, but legacy Endpoints remains an intentional compatibility fallback.

package kube

import (
	"context"
	"crypto/tls"
	"net/url"
	"strings"

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (c *Collector) limit() int64 { return c.Config.PageSize }

func (c *Collector) listPods(ctx context.Context, ns string) ([]corev1.Pod, error) {
	var out []corev1.Pod
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listNodes(ctx context.Context) ([]corev1.Node, error) {
	var out []corev1.Node
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listNodeLeases(ctx context.Context) ([]coordinationv1.Lease, error) {
	var out []coordinationv1.Lease
	cont := ""
	for {
		l, e := c.Clients.Kube.CoordinationV1().Leases(corev1.NamespaceNodeLease).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listServices(ctx context.Context, ns string) ([]corev1.Service, error) {
	var out []corev1.Service
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().Services(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}

func (c *Collector) listEndpoints(ctx context.Context, ns string) ([]corev1.Endpoints, error) {
	var out []corev1.Endpoints
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().Endpoints(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listEndpointSlices(ctx context.Context, ns string) ([]discoveryv1.EndpointSlice, error) {
	var out []discoveryv1.EndpointSlice
	cont := ""
	for {
		l, e := c.Clients.Kube.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listPVCs(ctx context.Context, ns string) ([]corev1.PersistentVolumeClaim, error) {
	var out []corev1.PersistentVolumeClaim
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().PersistentVolumeClaims(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listPVs(ctx context.Context) ([]corev1.PersistentVolume, error) {
	var out []corev1.PersistentVolume
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listConfigMaps(ctx context.Context, ns string) ([]corev1.ConfigMap, error) {
	var out []corev1.ConfigMap
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listSecrets(ctx context.Context, ns string) ([]SecretProjection, error) {
	var out []SecretProjection
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		for i := range l.Items {
			s := &l.Items[i]
			p := SecretProjection{Namespace: s.Namespace, Name: s.Name, Type: s.Type, Keys: map[string]struct{}{}}
			for k, v := range s.Data {
				p.Keys[k] = struct{}{}
				// Ingress accepts any Secret type as long as the conventional TLS
				// keys exist. Retain only tls.crt for validation and discard every
				// other value immediately below.
				if k == corev1.TLSCertKey {
					p.TLSCert = append([]byte(nil), v...)
				}
			}
			certificateData, certificateExists := s.Data[corev1.TLSCertKey]
			privateKeyData, privateKeyExists := s.Data[corev1.TLSPrivateKeyKey]
			if certificateExists && privateKeyExists {
				if len(privateKeyData) == 0 {
					p.TLSKeyPairError = corev1.TLSPrivateKeyKey + "が空です"
				} else if _, err := tls.X509KeyPair(certificateData, privateKeyData); err != nil {
					p.TLSKeyPairError = err.Error()
				}
			}
			out = append(out, p)
			for k, value := range s.Data {
				clear(value)
				delete(s.Data, k)
			}
		}
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listServiceAccounts(ctx context.Context, ns string) ([]corev1.ServiceAccount, error) {
	var out []corev1.ServiceAccount
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	var out []corev1.Namespace
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listEvents(ctx context.Context, ns string) ([]corev1.Event, error) {
	var out []corev1.Event
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().Events(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listResourceQuotas(ctx context.Context, ns string) ([]corev1.ResourceQuota, error) {
	var out []corev1.ResourceQuota
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().ResourceQuotas(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listLimitRanges(ctx context.Context, ns string) ([]corev1.LimitRange, error) {
	var out []corev1.LimitRange
	cont := ""
	for {
		l, e := c.Clients.Kube.CoreV1().LimitRanges(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listDeployments(ctx context.Context, ns string) ([]appsv1.Deployment, error) {
	var out []appsv1.Deployment
	cont := ""
	for {
		l, e := c.Clients.Kube.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listStatefulSets(ctx context.Context, ns string) ([]appsv1.StatefulSet, error) {
	var out []appsv1.StatefulSet
	cont := ""
	for {
		l, e := c.Clients.Kube.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listDaemonSets(ctx context.Context, ns string) ([]appsv1.DaemonSet, error) {
	var out []appsv1.DaemonSet
	cont := ""
	for {
		l, e := c.Clients.Kube.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listReplicaSets(ctx context.Context, ns string) ([]appsv1.ReplicaSet, error) {
	var out []appsv1.ReplicaSet
	cont := ""
	for {
		l, e := c.Clients.Kube.AppsV1().ReplicaSets(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listJobs(ctx context.Context, ns string) ([]batchv1.Job, error) {
	var out []batchv1.Job
	cont := ""
	for {
		l, e := c.Clients.Kube.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listCronJobs(ctx context.Context, ns string) ([]batchv1.CronJob, error) {
	var out []batchv1.CronJob
	cont := ""
	for {
		l, e := c.Clients.Kube.BatchV1().CronJobs(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listHPAs(ctx context.Context, ns string) ([]autoscalingv2.HorizontalPodAutoscaler, error) {
	var out []autoscalingv2.HorizontalPodAutoscaler
	cont := ""
	for {
		l, e := c.Clients.Kube.AutoscalingV2().HorizontalPodAutoscalers(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listIngresses(ctx context.Context, ns string) ([]networkingv1.Ingress, error) {
	var out []networkingv1.Ingress
	cont := ""
	for {
		l, e := c.Clients.Kube.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listIngressClasses(ctx context.Context) ([]networkingv1.IngressClass, error) {
	var out []networkingv1.IngressClass
	cont := ""
	for {
		l, e := c.Clients.Kube.NetworkingV1().IngressClasses().List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listNetworkPolicies(ctx context.Context, ns string) ([]networkingv1.NetworkPolicy, error) {
	var out []networkingv1.NetworkPolicy
	cont := ""
	for {
		l, e := c.Clients.Kube.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listValidatingWebhooks(ctx context.Context) ([]admissionv1.ValidatingWebhookConfiguration, error) {
	var out []admissionv1.ValidatingWebhookConfiguration
	cont := ""
	for {
		l, e := c.Clients.Kube.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listMutatingWebhooks(ctx context.Context) ([]admissionv1.MutatingWebhookConfiguration, error) {
	var out []admissionv1.MutatingWebhookConfiguration
	cont := ""
	for {
		l, e := c.Clients.Kube.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listStorageClasses(ctx context.Context) ([]storagev1.StorageClass, error) {
	var out []storagev1.StorageClass
	cont := ""
	for {
		l, e := c.Clients.Kube.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listPDBs(ctx context.Context, ns string) ([]policyv1.PodDisruptionBudget, error) {
	var out []policyv1.PodDisruptionBudget
	cont := ""
	for {
		l, e := c.Clients.Kube.PolicyV1().PodDisruptionBudgets(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listPriorityClasses(ctx context.Context) ([]schedulingv1.PriorityClass, error) {
	var out []schedulingv1.PriorityClass
	cont := ""
	for {
		l, e := c.Clients.Kube.SchedulingV1().PriorityClasses().List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listRuntimeClasses(ctx context.Context) ([]nodev1.RuntimeClass, error) {
	var out []nodev1.RuntimeClass
	cont := ""
	for {
		l, e := c.Clients.Kube.NodeV1().RuntimeClasses().List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.Continue
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) listDynamic(ctx context.Context, gvr schema.GroupVersionResource, ns string) ([]unstructured.Unstructured, error) {
	var out []unstructured.Unstructured
	cont := ""
	resource := c.Clients.Dynamic.Resource(gvr)
	for {
		var l *unstructured.UnstructuredList
		var e error
		if ns == "" {
			l, e = resource.List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		} else {
			l, e = resource.Namespace(ns).List(ctx, metav1.ListOptions{Limit: c.limit(), Continue: cont})
		}
		if e != nil {
			return out, e
		}
		out = append(out, l.Items...)
		cont = l.GetContinue()
		if cont == "" {
			return out, nil
		}
	}
}
func (c *Collector) raw(ctx context.Context, path string) (string, error) {
	base, rawQuery, _ := strings.Cut(path, "?")
	request := c.Clients.Kube.CoreV1().RESTClient().Get().AbsPath(base)
	if values, err := url.ParseQuery(rawQuery); err == nil {
		for key, entries := range values {
			if len(entries) == 0 {
				request.Param(key, "")
				continue
			}
			for _, value := range entries {
				request.Param(key, value)
			}
		}
	}
	data, err := request.DoRaw(ctx)
	return string(data), err
}
