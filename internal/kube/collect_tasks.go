package kube

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// collectTasks returns immutable task definitions. Workers only capture typed
// values in update closures; Collect applies those closures after Wait.
func (c *Collector) collectTasks(namespace string) []collectTask {
	tasks := []collectTask{
		{"pods", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listPods(ctx, namespace)
			return func(snapshot *Snapshot) {
				snapshot.Pods = values
				if namespace == metav1.NamespaceAll {
					snapshot.AllPods = append([]corev1.Pod{}, values...)
				}
			}, err
		}},
		{"nodes", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listNodes(ctx)
			return func(snapshot *Snapshot) { snapshot.Nodes = values }, err
		}},
		{"node_leases", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listNodeLeases(ctx)
			return func(snapshot *Snapshot) { snapshot.NodeLeases = values }, err
		}},
		{"services", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listServices(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.Services = values }, err
		}},
		{"endpoints", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listEndpoints(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.Endpoints = values }, err
		}},
		{"endpoint_slices", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listEndpointSlices(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.EndpointSlices = values }, err
		}},
		{"pvcs", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listPVCs(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.PersistentVolumeClaims = values }, err
		}},
		{"pvs", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listPVs(ctx)
			return func(snapshot *Snapshot) { snapshot.PersistentVolumes = values }, err
		}},
		{"configmaps", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listConfigMaps(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.ConfigMaps = values }, err
		}},
		{"secrets", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listSecrets(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.Secrets = values }, err
		}},
		{"serviceaccounts", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listServiceAccounts(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.ServiceAccounts = values }, err
		}},
		{"namespaces", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listNamespaces(ctx)
			return func(snapshot *Snapshot) { snapshot.Namespaces = values }, err
		}},
		{"events", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listEvents(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.Events = values }, err
		}},
		{"resourcequotas", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listResourceQuotas(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.ResourceQuotas = values }, err
		}},
		{"limitranges", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listLimitRanges(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.LimitRanges = values }, err
		}},
		{"deployments", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listDeployments(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.Deployments = values }, err
		}},
		{"statefulsets", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listStatefulSets(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.StatefulSets = values }, err
		}},
		{"daemonsets", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listDaemonSets(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.DaemonSets = values }, err
		}},
		{"replicasets", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listReplicaSets(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.ReplicaSets = values }, err
		}},
		{"jobs", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listJobs(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.Jobs = values }, err
		}},
		{"cronjobs", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listCronJobs(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.CronJobs = values }, err
		}},
		{"hpas", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listHPAs(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.HPAs = values }, err
		}},
		{"ingresses", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listIngresses(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.Ingresses = values }, err
		}},
		{"ingressclasses", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listIngressClasses(ctx)
			return func(snapshot *Snapshot) { snapshot.IngressClasses = values }, err
		}},
		{"networkpolicies", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listNetworkPolicies(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.NetworkPolicies = values }, err
		}},
		{"validatingwebhooks", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listValidatingWebhooks(ctx)
			return func(snapshot *Snapshot) { snapshot.ValidatingWebhooks = values }, err
		}},
		{"mutatingwebhooks", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listMutatingWebhooks(ctx)
			return func(snapshot *Snapshot) { snapshot.MutatingWebhooks = values }, err
		}},
		{"storageclasses", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listStorageClasses(ctx)
			return func(snapshot *Snapshot) { snapshot.StorageClasses = values }, err
		}},
		{"pdbs", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listPDBs(ctx, namespace)
			return func(snapshot *Snapshot) { snapshot.PodDisruptionBudgets = values }, err
		}},
		{"priorityclasses", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listPriorityClasses(ctx)
			return func(snapshot *Snapshot) { snapshot.PriorityClasses = values }, err
		}},
		{"runtimeclasses", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listRuntimeClasses(ctx)
			return func(snapshot *Snapshot) { snapshot.RuntimeClasses = values }, err
		}},
		{"node_metrics", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listDynamic(ctx, schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "nodes"}, "")
			return func(snapshot *Snapshot) { snapshot.NodeMetrics = values }, err
		}},
		{"pod_metrics", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listDynamic(ctx, schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "pods"}, namespace)
			return func(snapshot *Snapshot) { snapshot.PodMetrics = values }, err
		}},
		{"apiservices", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listDynamic(ctx, schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}, "")
			return func(snapshot *Snapshot) { snapshot.APIServices = values }, err
		}},
		{"crds", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listDynamic(ctx, schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}, "")
			return func(snapshot *Snapshot) { snapshot.CustomResourceDefs = values }, err
		}},
		{"readyz", func(ctx context.Context) (snapshotUpdate, error) {
			value, err := c.raw(ctx, "/readyz?verbose")
			return func(snapshot *Snapshot) { snapshot.Readyz = value }, err
		}},
		{"livez", func(ctx context.Context) (snapshotUpdate, error) {
			value, err := c.raw(ctx, "/livez?verbose")
			return func(snapshot *Snapshot) { snapshot.Livez = value }, err
		}},
	}
	wantsAllPods := len(c.Only) == 0 || c.Only["all_pods"]
	wantsScopedPods := len(c.Only) == 0 || c.Only["pods"]
	if namespace != metav1.NamespaceAll || wantsAllPods && !wantsScopedPods {
		tasks = append(tasks, collectTask{"all_pods", func(ctx context.Context) (snapshotUpdate, error) {
			values, err := c.listPods(ctx, metav1.NamespaceAll)
			return func(snapshot *Snapshot) { snapshot.AllPods = values }, err
		}})
	}
	return tasks
}
