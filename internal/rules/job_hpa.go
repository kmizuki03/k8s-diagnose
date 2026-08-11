package rules

import (
	"context"
	"fmt"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

type JobRule struct{}

func (JobRule) Metadata() Metadata {
	return Metadata{ID: "jobs", Section: "Job", Description: "Jobの終了条件と再試行状態", Required: []string{"jobs"}, Permissions: namespaced("batch", "jobs"), Modes: []string{"all", "triage"}}
}

func (JobRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.Jobs {
		job := &snapshot.Jobs[i]
		var failureTarget *batchv1.JobCondition
		for _, c := range job.Status.Conditions {
			if c.Status != corev1.ConditionTrue {
				continue
			}
			if c.Type == batchv1.JobFailed {
				failureTarget = nil
				result = append(result, jobFailureFinding(job, c))
				break
			}
			if c.Type == batchv1.JobFailureTarget {
				candidate := c
				failureTarget = &candidate
			}
		}
		if failureTarget != nil {
			result = append(result, jobFailureFinding(job, *failureTarget))
		}
	}
	return result
}

func jobFailureFinding(job *batchv1.Job, condition batchv1.JobCondition) model.Finding {
	message := fmt.Sprintf("Job %s は失敗しました%s", shortRef(job.Namespace, job.Name), reasonSuffix(condition.Reason))
	if condition.Type == batchv1.JobFailureTarget {
		message = fmt.Sprintf("Job %s は失敗条件を満たしており、終了処理を待っています%s", shortRef(job.Namespace, job.Name), reasonSuffix(condition.Reason))
	}
	return model.NewFinding(
		model.Issue, "K8S.JOB.FAILED", "Job", ref("Job", job.Namespace, job.Name), condition.Reason, string(condition.Type),
		message, 98,
		model.Evidence{Kind: "condition", Key: string(condition.Type), Value: condition.Message},
	)
}

type HPARule struct{}

func (HPARule) Metadata() Metadata {
	return Metadata{ID: "hpa", Section: "HPA", Description: "HPAの状態条件とレプリカ上限", Required: []string{"hpas"}, Permissions: namespaced("autoscaling", "horizontalpodautoscalers"), Modes: []string{"all", "triage"}}
}

func (HPARule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.HPAs {
		hpa := &snapshot.HPAs[i]
		if !statusGenerationPointerCurrent(hpa.Generation, hpa.Status.ObservedGeneration) {
			continue
		}
		resource := ref("HorizontalPodAutoscaler", hpa.Namespace, hpa.Name)
		for _, c := range hpa.Status.Conditions {
			if (c.Type == autoscalingv2.AbleToScale || c.Type == autoscalingv2.ScalingActive) && c.Status == "False" {
				result = append(result, model.NewFinding(model.Warning, "K8S.HPA.CONDITION", "HPA", resource, c.Reason, string(c.Type), conditionStateMessage("HPA", shortRef(hpa.Namespace, hpa.Name), string(c.Type), string(c.Status), c.Reason), 80, model.Evidence{Kind: "condition", Key: string(c.Type), Value: c.Message}))
			}
		}
		if hpa.Status.CurrentReplicas >= hpa.Spec.MaxReplicas && hpa.Status.DesiredReplicas >= hpa.Spec.MaxReplicas {
			result = append(result, model.NewFinding(model.Candidate, "K8S.HPA.SATURATED", "HPA", resource, "AtMaxReplicas", "max-replicas", fmt.Sprintf("HPA %s の現在のレプリカ数と希望レプリカ数は、どちらも上限 %d に達しています", shortRef(hpa.Namespace, hpa.Name), hpa.Spec.MaxReplicas), 55))
		}
	}
	return result
}
