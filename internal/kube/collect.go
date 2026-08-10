package kube

import (
	"context"
	"sync"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Collector struct {
	Clients *Clients
	Config  config.Config
	Only    map[string]bool
}

type collectTask struct {
	key string
	run func(context.Context) error
}

func (c *Collector) Collect(ctx context.Context) *Snapshot {
	c.Clients.BeginCollection()
	snapshot := NewSnapshot()
	namespace := c.Config.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}
	var mu sync.Mutex
	set := func(key string, err error) {
		mu.Lock()
		defer mu.Unlock()
		snapshot.Statuses[key] = FetchStatus{Available: err == nil, Status: ClassifyError(err), Reason: ErrorReason(err), HTTPCode: HTTPStatusCode(err)}
	}
	// Every task owns one Snapshot field. Pods is the sole apparent overlap:
	// when namespace==NamespaceAll the all_pods task returns before writing,
	// otherwise only all_pods writes AllPods. Statuses is protected by mu.
	// Keep this invariant when adding collectors; the race test in CI enforces it.
	tasks := []collectTask{
		{"pods", func(ctx context.Context) error {
			values, err := c.listPods(ctx, namespace)
			snapshot.Pods = values
			if namespace == metav1.NamespaceAll {
				snapshot.AllPods = append([]corev1.Pod{}, values...)
			}
			return err
		}},
		{"all_pods", func(ctx context.Context) error {
			if namespace == metav1.NamespaceAll {
				return nil
			}
			values, err := c.listPods(ctx, metav1.NamespaceAll)
			snapshot.AllPods = values
			return err
		}},
		{"nodes", func(ctx context.Context) error { values, err := c.listNodes(ctx); snapshot.Nodes = values; return err }},
		{"node_leases", func(ctx context.Context) error {
			values, err := c.listNodeLeases(ctx)
			snapshot.NodeLeases = values
			return err
		}},
		{"services", func(ctx context.Context) error {
			values, err := c.listServices(ctx, namespace)
			snapshot.Services = values
			return err
		}},
		{"endpoints", func(ctx context.Context) error {
			values, err := c.listEndpoints(ctx, namespace)
			snapshot.Endpoints = values
			return err
		}},
		{"endpoint_slices", func(ctx context.Context) error {
			values, err := c.listEndpointSlices(ctx, namespace)
			snapshot.EndpointSlices = values
			return err
		}},
		{"pvcs", func(ctx context.Context) error {
			values, err := c.listPVCs(ctx, namespace)
			snapshot.PersistentVolumeClaims = values
			return err
		}},
		{"pvs", func(ctx context.Context) error {
			values, err := c.listPVs(ctx)
			snapshot.PersistentVolumes = values
			return err
		}},
		{"configmaps", func(ctx context.Context) error {
			values, err := c.listConfigMaps(ctx, namespace)
			snapshot.ConfigMaps = values
			return err
		}},
		{"secrets", func(ctx context.Context) error {
			values, err := c.listSecrets(ctx, namespace)
			snapshot.Secrets = values
			return err
		}},
		{"serviceaccounts", func(ctx context.Context) error {
			values, err := c.listServiceAccounts(ctx, namespace)
			snapshot.ServiceAccounts = values
			return err
		}},
		{"namespaces", func(ctx context.Context) error {
			values, err := c.listNamespaces(ctx)
			snapshot.Namespaces = values
			return err
		}},
		{"events", func(ctx context.Context) error {
			values, err := c.listEvents(ctx, namespace)
			snapshot.Events = values
			return err
		}},
		{"resourcequotas", func(ctx context.Context) error {
			values, err := c.listResourceQuotas(ctx, namespace)
			snapshot.ResourceQuotas = values
			return err
		}},
		{"limitranges", func(ctx context.Context) error {
			values, err := c.listLimitRanges(ctx, namespace)
			snapshot.LimitRanges = values
			return err
		}},
		{"deployments", func(ctx context.Context) error {
			values, err := c.listDeployments(ctx, namespace)
			snapshot.Deployments = values
			return err
		}},
		{"statefulsets", func(ctx context.Context) error {
			values, err := c.listStatefulSets(ctx, namespace)
			snapshot.StatefulSets = values
			return err
		}},
		{"daemonsets", func(ctx context.Context) error {
			values, err := c.listDaemonSets(ctx, namespace)
			snapshot.DaemonSets = values
			return err
		}},
		{"replicasets", func(ctx context.Context) error {
			values, err := c.listReplicaSets(ctx, namespace)
			snapshot.ReplicaSets = values
			return err
		}},
		{"jobs", func(ctx context.Context) error {
			values, err := c.listJobs(ctx, namespace)
			snapshot.Jobs = values
			return err
		}},
		{"cronjobs", func(ctx context.Context) error {
			values, err := c.listCronJobs(ctx, namespace)
			snapshot.CronJobs = values
			return err
		}},
		{"hpas", func(ctx context.Context) error {
			values, err := c.listHPAs(ctx, namespace)
			snapshot.HPAs = values
			return err
		}},
		{"ingresses", func(ctx context.Context) error {
			values, err := c.listIngresses(ctx, namespace)
			snapshot.Ingresses = values
			return err
		}},
		{"ingressclasses", func(ctx context.Context) error {
			values, err := c.listIngressClasses(ctx)
			snapshot.IngressClasses = values
			return err
		}},
		{"networkpolicies", func(ctx context.Context) error {
			values, err := c.listNetworkPolicies(ctx, namespace)
			snapshot.NetworkPolicies = values
			return err
		}},
		{"validatingwebhooks", func(ctx context.Context) error {
			values, err := c.listValidatingWebhooks(ctx)
			snapshot.ValidatingWebhooks = values
			return err
		}},
		{"mutatingwebhooks", func(ctx context.Context) error {
			values, err := c.listMutatingWebhooks(ctx)
			snapshot.MutatingWebhooks = values
			return err
		}},
		{"storageclasses", func(ctx context.Context) error {
			values, err := c.listStorageClasses(ctx)
			snapshot.StorageClasses = values
			return err
		}},
		{"pdbs", func(ctx context.Context) error {
			values, err := c.listPDBs(ctx, namespace)
			snapshot.PodDisruptionBudgets = values
			return err
		}},
		{"priorityclasses", func(ctx context.Context) error {
			values, err := c.listPriorityClasses(ctx)
			snapshot.PriorityClasses = values
			return err
		}},
		{"runtimeclasses", func(ctx context.Context) error {
			values, err := c.listRuntimeClasses(ctx)
			snapshot.RuntimeClasses = values
			return err
		}},
		{"node_metrics", func(ctx context.Context) error {
			values, err := c.listDynamic(ctx, schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "nodes"}, "")
			snapshot.NodeMetrics = values
			return err
		}},
		{"pod_metrics", func(ctx context.Context) error {
			values, err := c.listDynamic(ctx, schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "pods"}, namespace)
			snapshot.PodMetrics = values
			return err
		}},
		{"apiservices", func(ctx context.Context) error {
			values, err := c.listDynamic(ctx, schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"}, "")
			snapshot.APIServices = values
			return err
		}},
		{"crds", func(ctx context.Context) error {
			values, err := c.listDynamic(ctx, schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}, "")
			snapshot.CustomResourceDefs = values
			return err
		}},
		{"readyz", func(ctx context.Context) error {
			value, err := c.raw(ctx, "/readyz?verbose")
			snapshot.Readyz = value
			return err
		}},
		{"livez", func(ctx context.Context) error {
			value, err := c.raw(ctx, "/livez?verbose")
			snapshot.Livez = value
			return err
		}},
	}
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(max(1, min(c.Config.Workers, 16)))
	for _, task := range tasks {
		task := task
		if len(c.Only) > 0 && !c.Only[task.key] {
			continue
		}
		group.Go(func() error { err := task.run(groupContext); set(task.key, err); return nil })
	}
	_ = group.Wait()
	snapshot.APIWarnings = c.Clients.DrainWarnings()
	snapshot.ServerTime = c.Clients.ServerTime()
	return snapshot
}

func listOptions(limit int64, fieldSelector string) metav1.ListOptions {
	return metav1.ListOptions{Limit: limit, FieldSelector: fieldSelector}
}
