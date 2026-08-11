package kube

import (
	"context"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Collector struct {
	Clients *Clients
	Config  config.Config
	Only    map[string]bool
}

type snapshotUpdate func(*Snapshot)

type collectTask struct {
	key string
	run func(context.Context) (snapshotUpdate, error)
}

type collectResult struct {
	key    string
	update snapshotUpdate
	err    error
}

func (c *Collector) Collect(ctx context.Context) *Snapshot {
	c.Clients.BeginCollection()
	snapshot := NewSnapshot()
	namespace := c.Config.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	tasks := c.collectTasks(namespace)
	results := make(chan collectResult, len(tasks))
	group, groupContext := errgroup.WithContext(ctx)
	group.SetLimit(max(1, min(c.Config.Workers, 16)))
	for _, task := range tasks {
		task := task
		if len(c.Only) > 0 && !c.Only[task.key] {
			continue
		}
		group.Go(func() error {
			update, err := task.run(groupContext)
			results <- collectResult{key: task.key, update: update, err: err}
			return nil
		})
	}
	_ = group.Wait()
	close(results)

	// API calls run concurrently, but Snapshot is populated serially after all
	// workers finish. Adding a new task therefore cannot accidentally introduce
	// a concurrent struct-field write.
	for result := range results {
		if result.update != nil {
			result.update(snapshot)
		}
		snapshot.Statuses[result.key] = fetchStatus(result.err)
	}
	// A cluster-wide Pod list already serves both views. Reuse its exact status
	// (including RBAC/API failure) instead of issuing a duplicate request.
	if namespace == metav1.NamespaceAll && (len(c.Only) == 0 || c.Only["all_pods"]) {
		if status, collected := snapshot.Statuses["pods"]; collected {
			snapshot.Statuses["all_pods"] = status
		}
	}
	snapshot.APIWarnings = c.Clients.DrainWarnings()
	snapshot.ServerTime = c.Clients.ServerTime()
	return snapshot
}

func fetchStatus(err error) FetchStatus {
	return FetchStatus{
		Available: err == nil,
		Status:    ClassifyError(err),
		Reason:    ErrorReason(err),
		HTTPCode:  HTTPStatusCode(err),
	}
}

func listOptions(limit int64, fieldSelector string) metav1.ListOptions {
	return metav1.ListOptions{Limit: limit, FieldSelector: fieldSelector}
}
