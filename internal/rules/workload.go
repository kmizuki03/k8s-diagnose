package rules

import (
	"context"
	"fmt"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	appsv1 "k8s.io/api/apps/v1"
)

type WorkloadRule struct{}

func (WorkloadRule) Metadata() Metadata {
	return Metadata{
		ID: "workloads", Section: "ワークロード（Deploymentなど）", Description: "ワークロードのレプリカ数とロールアウト状態",
		Required:    []string{"deployments", "statefulsets", "daemonsets", "replicasets"},
		Permissions: namespaced("apps", "deployments,statefulsets,daemonsets,replicasets"),
		Modes:       []string{"all", "triage"},
	}
}

func (WorkloadRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.Deployments {
		deployment := &snapshot.Deployments[i]
		if !statusGenerationCurrent(deployment.Generation, deployment.Status.ObservedGeneration) {
			continue
		}
		resource := ref("Deployment", deployment.Namespace, deployment.Name)
		short := shortRef(deployment.Namespace, deployment.Name)
		normalRollout := false
		hardRolloutFailure := false
		for _, c := range deployment.Status.Conditions {
			if c.Type == appsv1.DeploymentProgressing && c.Status == "False" && c.Reason == "ProgressDeadlineExceeded" {
				hardRolloutFailure = true
				result = append(result, model.NewFinding(
					model.Issue, "K8S.WORKLOAD.PROGRESS_DEADLINE_EXCEEDED", "ワークロード（Deploymentなど）", resource,
					c.Reason, "progress-deadline", fmt.Sprintf("Deployment %s のロールアウトは、progressDeadlineSecondsを超えても完了していません", short), 100,
					model.Evidence{Kind: "condition", Key: string(c.Type), Value: c.Message},
				))
			}
			if c.Type == appsv1.DeploymentReplicaFailure && c.Status == "True" {
				hardRolloutFailure = true
				result = append(result, model.NewFinding(
					model.Issue, "K8S.WORKLOAD.REPLICA_FAILURE", "ワークロード（Deploymentなど）", resource,
					c.Reason, "replica-failure", fmt.Sprintf("Deployment %s はレプリカ（Pod）を作成できません%s", short, reasonSuffix(c.Reason)), 100,
					model.Evidence{Kind: "condition", Key: string(c.Type), Value: c.Message},
				))
			}
			if c.Type == appsv1.DeploymentProgressing && c.Status == "True" && (c.Reason == "NewReplicaSetCreated" || c.Reason == "FoundNewReplicaSet" || c.Reason == "ReplicaSetUpdated") {
				normalRollout = true
			}
		}
		desired := int32Value(deployment.Spec.Replicas, 1)
		if desired > 0 && deployment.Status.ReadyReplicas < desired && (!normalRollout || hardRolloutFailure) {
			result = append(result, model.NewFinding(
				model.Warning, "K8S.WORKLOAD.REPLICAS_UNAVAILABLE", "ワークロード（Deploymentなど）", resource,
				"ReadyReplicasUnavailable", "ready-replicas", readyCountMessage("Deployment", short, deployment.Status.ReadyReplicas, desired), 75,
				model.Evidence{Kind: "status", Key: "readyReplicas", Value: fmt.Sprintf("%d/%d", deployment.Status.ReadyReplicas, desired)},
			))
		}
	}
	for i := range snapshot.ReplicaSets {
		rs := &snapshot.ReplicaSets[i]
		if !statusGenerationCurrent(rs.Generation, rs.Status.ObservedGeneration) {
			continue
		}
		for _, c := range rs.Status.Conditions {
			if c.Type == appsv1.ReplicaSetReplicaFailure && c.Status == "True" {
				result = append(result, model.NewFinding(
					model.Issue, "K8S.WORKLOAD.REPLICA_FAILURE", "ワークロード（Deploymentなど）", ref("ReplicaSet", rs.Namespace, rs.Name),
					c.Reason, "replica-failure", fmt.Sprintf("ReplicaSet %s はレプリカ（Pod）を作成できません%s", shortRef(rs.Namespace, rs.Name), reasonSuffix(c.Reason)), 100,
					model.Evidence{Kind: "condition", Key: string(c.Type), Value: c.Message},
				))
			}
		}
	}
	for i := range snapshot.StatefulSets {
		item := &snapshot.StatefulSets[i]
		if !statusGenerationCurrent(item.Generation, item.Status.ObservedGeneration) {
			continue
		}
		desired := int32Value(item.Spec.Replicas, 1)
		if desired > 0 && item.Status.ReadyReplicas < desired {
			result = append(result, model.NewFinding(model.Warning, "K8S.WORKLOAD.REPLICAS_UNAVAILABLE", "ワークロード（Deploymentなど）", ref("StatefulSet", item.Namespace, item.Name), "ReadyReplicasUnavailable", "ready-replicas", readyCountMessage("StatefulSet", shortRef(item.Namespace, item.Name), item.Status.ReadyReplicas, desired), 75))
		}
	}
	for i := range snapshot.DaemonSets {
		item := &snapshot.DaemonSets[i]
		if !statusGenerationCurrent(item.Generation, item.Status.ObservedGeneration) {
			continue
		}
		if item.Status.DesiredNumberScheduled > 0 && item.Status.NumberReady < item.Status.DesiredNumberScheduled {
			result = append(result, model.NewFinding(model.Warning, "K8S.WORKLOAD.REPLICAS_UNAVAILABLE", "ワークロード（Deploymentなど）", ref("DaemonSet", item.Namespace, item.Name), "ReadyReplicasUnavailable", "ready-replicas", readyCountMessage("DaemonSet", shortRef(item.Namespace, item.Name), item.Status.NumberReady, item.Status.DesiredNumberScheduled), 75))
		}
	}
	return result
}
