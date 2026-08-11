package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
)

const maxLogBytesPerContainer = 512 * 1024

func (runner *Runner) collectLogs(ctx context.Context, snapshot *kube.Snapshot, state *model.State, selected bool) {
	referenceTime := snapshot.ServerTime
	if referenceTime.IsZero() {
		referenceTime = time.Now()
	}
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		if !selected && isHealthyPod(pod, runner.Config, referenceTime) {
			continue
		}
		for _, previous := range []bool{false, true} {
			logs, failures := runner.podLogs(ctx, pod, previous)
			source := "current"
			if previous {
				source = "previous"
			}
			checkID := "logs/" + pod.Namespace + "/" + pod.Name + "/" + source
			state.AddCheck(model.Check{ID: checkID, Section: "ログ", Description: fmt.Sprintf("Pod %s/%sの%sログ", pod.Namespace, pod.Name, source), Available: len(failures) == 0, Reason: strings.Join(failures, "; ")})
			if len(failures) > 0 {
				finding := model.NewFinding(model.Unavailable, "K8S.LOG.FETCH_UNAVAILABLE", "ログ", "Pod/"+pod.Namespace+"/"+pod.Name, "LogFetchFailed", source, fmt.Sprintf("Pod %s/%sの%sログを一部またはすべて取得できませんでした", pod.Namespace, pod.Name, source), 100, model.Evidence{Kind: "api", Key: "errors", Value: strings.Join(failures, "; ")})
				finding.RuleID = "logs"
				state.Add(finding)
			}
			for _, log := range logs {
				logSource := source + "/" + log.Container
				for _, finding := range runner.LogAnalyzer.Analyze(pod.Namespace, pod.Name, logSource, log.Text) {
					finding.RuleID = "logs"
					state.Add(finding)
				}
				lines := tailLines(log.Text, runner.Config.Tail)
				for index := range lines {
					lines[index] = console.MaskSecrets(lines[index], runner.Config.Mask)
				}
				runner.logBlocks = append(runner.logBlocks, logBlock{
					Title:   fmt.Sprintf("ログ %s/%s [%s] (%s)", pod.Namespace, pod.Name, log.Container, source),
					Lines:   lines,
					Command: log.Command,
				})
			}
		}
	}
}

func (runner *Runner) renderLogs() {
	shown := map[string]struct{}{}
	for _, block := range runner.logBlocks {
		runner.Console.Section(block.Title)
		if len(block.Command) > 0 {
			shown[strings.Join(block.Command, "\x00")] = struct{}{}
			runner.renderCommandGroup([][]string{block.Command})
		}
		for _, line := range block.Lines {
			runner.Console.Write(line)
		}
	}
	remaining := [][]string{}
	for _, command := range runner.kubectlCmds {
		if _, ok := shown[strings.Join(command, "\x00")]; !ok {
			remaining = append(remaining, command)
		}
	}
	runner.kubectlCmds = nil
	if len(remaining) > 0 {
		runner.Console.Section("ログ診断（本文なし・取得不能を含む）")
		runner.renderCommandGroup(remaining)
		runner.Console.Write("  ログ本文を表示できなかった取得対象です。上のコマンドで個別に確認できます。")
	}
}

func (runner *Runner) podLogs(ctx context.Context, pod *corev1.Pod, previous bool) ([]containerLog, []string) {
	tail := int64(max(runner.Config.Tail, runner.Config.LogSignatureLines))
	names := []string{}
	for _, container := range pod.Spec.InitContainers {
		names = append(names, container.Name)
	}
	for _, container := range pod.Spec.Containers {
		names = append(names, container.Name)
	}
	for _, container := range pod.Spec.EphemeralContainers {
		names = append(names, container.Name)
	}
	logs := []containerLog{}
	failures := []string{}
	for _, name := range names {
		args := []string{"logs", pod.Name, "-n", pod.Namespace, "-c", name, "--tail=" + strconv.FormatInt(tail, 10)}
		if previous {
			args = append(args, "--previous")
		}
		command := kube.KubectlCommand(runner.Config, args...)
		runner.kubectlCmds = append(runner.kubectlCmds, command)
		data, err := runner.Clients.Kube.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{Container: name, Previous: previous, TailLines: &tail}).DoRaw(ctx)
		if err != nil {
			lower := strings.ToLower(err.Error())
			if previous && (strings.Contains(lower, "previous terminated container") || strings.Contains(lower, "not found")) {
				continue
			}
			failures = append(failures, name+": "+kube.ErrorReason(err))
			continue
		}
		text := newestBytes(string(data), maxLogBytesPerContainer)
		if text != "" {
			logs = append(logs, containerLog{Container: name, Text: text, Command: command})
		}
	}
	return logs, failures
}

func isHealthyPod(pod *corev1.Pod, cfg config.Config, now time.Time) bool {
	if pod.DeletionTimestamp != nil {
		return false
	}
	if pod.Status.Phase == corev1.PodSucceeded {
		return true
	}
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	ready := false
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			ready = condition.Status == corev1.ConditionTrue
		}
		if condition.Type == corev1.DisruptionTarget && condition.Status == corev1.ConditionTrue || condition.Type == corev1.PodReadyToStartContainers && condition.Status == corev1.ConditionFalse {
			return false
		}
	}
	if !ready {
		return false
	}
	statuses := append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	statuses = append(statuses, pod.Status.ContainerStatuses...)
	for _, status := range statuses {
		if status.State.Waiting != nil && status.State.Waiting.Reason != "" {
			return false
		}
		if status.State.Terminated != nil && status.State.Terminated.Reason != "" && status.State.Terminated.Reason != "Completed" {
			return false
		}
		terminated := status.LastTerminationState.Terminated
		if terminated == nil || terminated.FinishedAt.IsZero() {
			continue
		}
		age := now.Sub(terminated.FinishedAt.Time)
		recent := age <= 24*time.Hour
		if recent && (terminated.Reason == "OOMKilled" || int64(status.RestartCount) >= int64(cfg.RestartThreshold)) {
			return false
		}
	}
	return true
}

func newestBytes(value string, maximum int) string {
	data := []byte(value)
	if len(data) <= maximum {
		return value
	}
	data = data[len(data)-maximum:]
	for len(data) > 0 && data[0]&0xc0 == 0x80 {
		data = data[1:]
	}
	return string(data)
}

func tailLines(value string, count int) []string {
	lines := strings.Split(strings.TrimRight(value, "\n"), "\n")
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	return lines
}
