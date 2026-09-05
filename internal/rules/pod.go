package rules

import (
	"context"
	"fmt"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
)

// PodHealthRule separates confirmed container failures from ordinary lifecycle
// transitions. This mirrors the Python version's conservative CI policy.
type PodHealthRule struct{}

func (PodHealthRule) Metadata() Metadata {
	return Metadata{
		ID: "pod-health", Section: "Pod", Description: "Podとコンテナの稼働状態",
		Required: []string{"pods"}, Permissions: namespaced("", "pods"),
		Modes: []string{"all", "triage", "select"},
	}
}

func (PodHealthRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, cfg config.Config) []model.Finding {
	findings := []model.Finding{}
	now := evaluationTime(snapshot)
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		resource := ref("Pod", pod.Namespace, pod.Name)
		short := shortRef(pod.Namespace, pod.Name)
		if pod.DeletionTimestamp != nil && now.Sub(pod.DeletionTimestamp.Time) >= 5*time.Minute {
			minutes := int(now.Sub(pod.DeletionTimestamp.Time).Minutes())
			findings = append(findings, model.NewFinding(
				model.Warning, "K8S.POD.TERMINATING_STATE", "Pod", resource,
				"Terminating", "terminating", fmt.Sprintf("Pod %s の削除処理が完了せず、Terminating 状態が %d分間続いています", short, max(0, minutes)), 70,
				model.Evidence{Kind: "pod", Key: "deletionTimestamp", Value: pod.DeletionTimestamp.String()},
			))
		}

		jobPod := podOwnedByJob(pod)
		hasConfirmedFailure := false
		for _, status := range workloadContainerStatuses(pod) {
			reason := statusReason(status)
			if reason == "" {
				continue
			}
			message := containerStateMessage(short, status, reason)
			if detail := messageForStatus(status); detail != "" {
				message += "。詳細: " + detail
			}
			severity := model.Warning
			code := "K8S.POD.NON_RUNNING_STATE"
			confidence := 70
			if confirmedWaiting[reason] || reason == "OOMKilled" || reason == "ContainerCannotRun" {
				severity, code, confidence = model.Issue, "K8S.POD.ABNORMAL_STATE", 100
				hasConfirmedFailure = true
			}
			if jobPod && severity == model.Issue {
				severity, code, confidence = model.Warning, "K8S.POD.JOB_ATTEMPT_FAILED", 75
			}
			findings = append(findings, model.NewFinding(
				severity, code, "Pod", resource, reason, status.Name+"/"+reason, message, confidence,
				model.Evidence{Kind: "container", Key: "state", Value: reason},
			))
		}
		if pod.Status.Phase == corev1.PodFailed && !jobPod && !hasConfirmedFailure {
			reason := pod.Status.Reason
			if reason == "" {
				reason = "Failed"
			}
			message := fmt.Sprintf("Pod %s の状態（phase）は Failed です%s", short, reasonSuffix(pod.Status.Reason))
			if pod.Status.Message != "" {
				message += "。詳細: " + pod.Status.Message
			}
			findings = append(findings, model.NewFinding(
				model.Issue, "K8S.POD.FAILED_PHASE", "Pod", resource, reason, "failed-phase", message, 100,
				model.Evidence{Kind: "pod", Key: "phase", Value: string(pod.Status.Phase)},
			))
			hasConfirmedFailure = true
		}
		if pod.Status.Phase == corev1.PodUnknown {
			findings = append(findings, model.NewFinding(
				model.Warning, "K8S.POD.UNKNOWN_PHASE", "Pod", resource, pod.Status.Reason, "unknown-phase",
				fmt.Sprintf("Pod %s の状態（phase）は Unknown で、現在の稼働状態を確認できません%s", short, reasonSuffix(pod.Status.Reason)), 85,
				model.Evidence{Kind: "pod", Key: "phase", Value: string(pod.Status.Phase)},
			))
		}

		if ready := condition(pod.Status.Conditions, corev1.PodReady); !hasConfirmedFailure && ready != nil && ready.Status != corev1.ConditionTrue && pod.Status.Phase == corev1.PodRunning {
			findings = append(findings, model.NewFinding(
				model.Warning, "K8S.POD.NOT_READY", "Pod", resource, string(ready.Reason), "ready-condition",
				conditionStateMessage("Pod", short, string(corev1.PodReady), string(ready.Status), ready.Reason), 80,
				model.Evidence{Kind: "condition", Key: "Ready", Value: string(ready.Status)},
			))
		}
		for _, podCondition := range pod.Status.Conditions {
			switch {
			case podCondition.Type == corev1.DisruptionTarget && podCondition.Status == corev1.ConditionTrue:
				findings = append(findings, model.NewFinding(
					model.Warning, "K8S.POD.DISRUPTION_TARGET", "Pod", resource, podCondition.Reason, "disruption-target",
					fmt.Sprintf("Pod %s は、EvictionまたはPreemptionなどによる終了対象になっています%s", short, reasonSuffix(podCondition.Reason)), 90,
					model.Evidence{Kind: "condition", Key: string(podCondition.Type), Value: podCondition.Message},
				))
			case podCondition.Type == corev1.PodReadyToStartContainers &&
				podCondition.Status == corev1.ConditionFalse &&
				pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed:
				findings = append(findings, model.NewFinding(
					model.Warning, "K8S.POD.SANDBOX_NOT_READY", "Pod", resource, podCondition.Reason, "sandbox-not-ready",
					fmt.Sprintf("Pod %s では、Podサンドボックスまたはネットワークの準備が完了していません%s", short, reasonSuffix(podCondition.Reason)), 85,
					model.Evidence{Kind: "condition", Key: string(podCondition.Type), Value: podCondition.Message},
				))
			}
		}

		for _, status := range workloadContainerStatuses(pod) {
			if terminated := status.LastTerminationState.Terminated; terminated != nil && terminated.Reason == "OOMKilled" && !terminated.FinishedAt.IsZero() && elapsedSince(snapshot, terminated.FinishedAt.Time) <= 24*time.Hour {
				findings = append(findings, model.NewFinding(
					model.Warning, "K8S.POD.PREVIOUS_OOM_KILLED", "Pod", resource, "PreviousOOMKilled", status.Name+"/previous-oom-killed",
					fmt.Sprintf("Pod %s のコンテナ %q は、直近24時間以内にメモリ不足で強制終了しています（OOMKilled）", short, status.Name), 90,
					model.Evidence{Kind: "container", Key: "lastTerminationReason", Value: terminated.Reason},
					model.Evidence{Kind: "container", Key: "lastExitCode", Value: fmt.Sprint(terminated.ExitCode)},
				))
			}
			if int64(status.RestartCount) < int64(cfg.RestartThreshold) {
				continue
			}
			recent := false
			if terminated := status.LastTerminationState.Terminated; terminated != nil && !terminated.FinishedAt.IsZero() {
				recent = elapsedSince(snapshot, terminated.FinishedAt.Time) <= 24*time.Hour
			}
			if !recent {
				continue
			}
			findings = append(findings, model.NewFinding(
				model.Warning, "K8S.POD.RECENT_RESTARTS", "Pod", resource, "RecentRestarts", status.Name+"/recent-restarts",
				fmt.Sprintf("Pod %s のコンテナ %q は直近24時間以内に再起動しており、累計再起動回数は%d回です", short, status.Name, status.RestartCount), 75,
				model.Evidence{Kind: "container", Key: "restartCount", Value: fmt.Sprint(status.RestartCount)},
			))
		}

		if pod.Status.Phase == corev1.PodPending && !hasConfirmedFailure {
			findings = append(findings, model.NewFinding(
				model.Warning, "K8S.POD.PENDING_STATE", "Pod", resource, pod.Status.Reason, "pending",
				fmt.Sprintf("Pod %s は Pending 状態で、Nodeへの配置またはコンテナの起動を待っています", short), 60,
				model.Evidence{Kind: "pod", Key: "phase", Value: string(pod.Status.Phase)},
			))
		}
	}
	return findings
}

func containerStateMessage(pod string, status corev1.ContainerStatus, reason string) string {
	if status.State.Waiting != nil {
		return fmt.Sprintf("Pod %s のコンテナ %q は起動を待っています%s", pod, status.Name, reasonSuffix(reason))
	}
	if status.State.Terminated != nil {
		return fmt.Sprintf("Pod %s のコンテナ %q は終了しました（理由: %s、終了コード: %d）", pod, status.Name, reason, status.State.Terminated.ExitCode)
	}
	return fmt.Sprintf("Pod %s のコンテナ %q は正常に稼働していません%s", pod, status.Name, reasonSuffix(reason))
}
