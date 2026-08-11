package rules

import (
	"context"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

// NodeMetricsRule preserves the Python implementation's stable unavailable
// identity so snapshots, baselines and parity comparisons survive migration.
type NodeMetricsRule struct{}

func (NodeMetricsRule) Metadata() Metadata {
	return Metadata{
		ID: "node-metrics", Section: "メトリクス", Description: "Node使用量",
		Required: []string{"node_metrics"}, UnavailableCode: "K8S.METRICS.EC8CBD04",
		Permissions: cluster("metrics.k8s.io", "nodes"), Modes: []string{"all"},
	}
}

func (NodeMetricsRule) Evaluate(context.Context, *kube.Snapshot, config.Config) []model.Finding {
	return nil
}

// PodMetricsRule tracks Pod metrics as an independent Coverage unit.
type PodMetricsRule struct{}

func (PodMetricsRule) Metadata() Metadata {
	return Metadata{
		ID: "pod-metrics", Section: "メトリクス", Description: "Pod使用量",
		Required: []string{"pod_metrics"}, UnavailableCode: "K8S.METRICS.D0439E88",
		Permissions: namespaced("metrics.k8s.io", "pods"), Modes: []string{"all", "select"},
	}
}

func (PodMetricsRule) Evaluate(context.Context, *kube.Snapshot, config.Config) []model.Finding {
	return nil
}
