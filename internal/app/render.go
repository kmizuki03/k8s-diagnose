package app

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/history"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
)

func (runner *Runner) renderText(snapshot *kube.Snapshot, state *model.State) {
	runner.Console.Header(runner.Clients.Context)
	if runner.Config.Mode == "all" {
		runner.Console.Chapter("Pod一覧")
		runner.renderCommandsForKeys(snapshot, "pods")
		runner.Console.PodTable([]string{"NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE", "NODE"}, podRows(snapshot.Pods))
		runner.renderMetrics(snapshot, state)
	}
	runner.Console.DiagnosticContents(runner.diagnosticItems(snapshot, state))
	runner.renderEvents(snapshot, snapshot.Events, "")
	runner.renderLogs()
	runner.Console.RootCauseReport(state.RootCauses)
	if runner.History != nil {
		runner.renderHistory(*runner.History)
	}
	runner.Console.Summary(state, func(finding model.Finding) {
		runner.renderCommandsForFinding(snapshot, finding)
	})
	runner.renderTrace()
}

func (runner *Runner) renderEvents(snapshot *kube.Snapshot, events []corev1.Event, podName string) {
	type timedEvent struct {
		event corev1.Event
		when  time.Time
	}
	values := []timedEvent{}
	for i := range events {
		event := events[i]
		if event.Type != corev1.EventTypeWarning {
			continue
		}
		if podName != "" && !(event.InvolvedObject.Kind == "Pod" && event.InvolvedObject.Name == podName) {
			continue
		}
		when := latestEventTime(&event)
		values = append(values, timedEvent{event: event, when: when})
	}
	sort.SliceStable(values, func(i, j int) bool { return values[i].when.After(values[j].when) })
	if len(values) > runner.Config.EventsLimit {
		values = values[:runner.Config.EventsLimit]
	}
	if len(values) == 0 {
		return
	}
	runner.Console.Chapter(fmt.Sprintf("警告イベント（最新%d件）", len(values)))
	runner.renderCommandsForKeys(snapshot, "events")
	rows := make([]console.TableRow, 0, len(values))
	for _, value := range values {
		event := value.event
		rows = append(rows, console.TableRow{Cells: []string{
			event.Namespace, event.InvolvedObject.Kind + "/" + event.InvolvedObject.Name,
			event.Reason, ageText(value.when), console.Snip(console.MaskSecrets(strings.Join(strings.Fields(event.Message), " "), runner.Config.Mask), 120),
		}, Status: "Warning"})
	}
	runner.Console.Table([]string{"NAMESPACE", "OBJECT", "REASON", "AGE", "MESSAGE"}, rows, true)
}

func latestEventTime(event *corev1.Event) time.Time {
	latest := event.CreationTimestamp.Time
	for _, candidate := range []time.Time{event.FirstTimestamp.Time, event.LastTimestamp.Time, event.EventTime.Time} {
		if candidate.After(latest) {
			latest = candidate
		}
	}
	if event.Series != nil && event.Series.LastObservedTime.Time.After(latest) {
		latest = event.Series.LastObservedTime.Time
	}
	return latest
}

func (runner *Runner) renderTrace() {
	if runner.trace == nil || runner.trace.Len() == 0 {
		return
	}
	if !runner.Config.ShowAPIRequests || runner.Config.Output != "text" {
		runner.trace.Reset()
		return
	}
	runner.Console.Section("実行したKubernetes API要求")
	for _, line := range strings.Split(strings.TrimRight(runner.trace.String(), "\n"), "\n") {
		runner.Console.Write(line)
	}
	runner.trace.Reset()
}

func (runner *Runner) renderHistory(analysis history.Analysis) {
	runner.Console.Section("履歴トレンド")
	if len(analysis.Trends) == 0 {
		runner.Console.Write(fmt.Sprintf("直近%d回ではフラッピング・継続的な再起動増加を検出しませんでした", analysis.Samples))
	} else {
		for _, trend := range analysis.Trends {
			runner.Console.Write("  ▲ " + console.MaskSecrets(trend.Message, runner.Config.Mask))
		}
		runner.Console.Write(fmt.Sprintf("  （所見 %d件・分析対象 %d回）", len(analysis.Trends), analysis.Samples))
	}
	if analysis.UnknownEvaluations > 0 {
		runner.Console.Write(fmt.Sprintf("  状態を確認できなかった %d件は、正常・異常の遷移判定から除外しました", analysis.UnknownEvaluations))
	}
}

func podRows(pods []corev1.Pod) []console.TableRow {
	values := append([]corev1.Pod{}, pods...)
	sort.Slice(values, func(i, j int) bool {
		return values[i].Namespace+"/"+values[i].Name < values[j].Namespace+"/"+values[j].Name
	})
	result := make([]console.TableRow, 0, len(values))
	for i := range values {
		pod := &values[i]
		ready, total := readyRatio(pod)
		restarts := int32(0)
		for _, status := range append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
			restarts += status.RestartCount
		}
		result = append(result, console.TableRow{Cells: []string{pod.Namespace, pod.Name, fmt.Sprintf("%d/%d", ready, total), podStatus(pod), fmt.Sprint(restarts), ageText(pod.CreationTimestamp.Time), valueOr(pod.Spec.NodeName, "<none>")}, Status: podStatus(pod)})
	}
	return result
}

func readyRatio(pod *corev1.Pod) (int, int) {
	ready, total := 0, 0
	for _, container := range pod.Spec.InitContainers {
		if container.RestartPolicy == nil || *container.RestartPolicy != corev1.ContainerRestartPolicyAlways {
			continue
		}
		total++
		for _, status := range pod.Status.InitContainerStatuses {
			if status.Name == container.Name && status.Ready {
				ready++
				break
			}
		}
	}
	for _, container := range pod.Spec.Containers {
		total++
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == container.Name && status.Ready {
				ready++
				break
			}
		}
	}
	return ready, total
}

func podStatus(pod *corev1.Pod) string {
	if pod.DeletionTimestamp != nil {
		return "Terminating"
	}
	statuses := append(append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	for _, status := range statuses {
		if status.State.Waiting != nil && status.State.Waiting.Reason != "" {
			return status.State.Waiting.Reason
		}
		if status.State.Terminated != nil && status.State.Terminated.Reason != "" && status.State.Terminated.Reason != "Completed" {
			return status.State.Terminated.Reason
		}
	}
	if pod.Status.Reason != "" {
		return pod.Status.Reason
	}
	if pod.Status.Phase == corev1.PodRunning {
		ready, total := readyRatio(pod)
		if ready < total {
			return "NotReady"
		}
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status != corev1.ConditionTrue {
				return "NotReady"
			}
		}
	}
	if pod.Status.Phase != "" {
		return string(pod.Status.Phase)
	}
	return "Unknown"
}

func ageText(created time.Time) string {
	if created.IsZero() {
		return "<unknown>"
	}
	duration := time.Since(created)
	if duration < time.Minute {
		return fmt.Sprintf("%ds", max(0, int(duration.Seconds())))
	}
	if duration < time.Hour {
		return fmt.Sprintf("%dm", int(duration.Minutes()))
	}
	if duration < 24*time.Hour {
		return fmt.Sprintf("%dh", int(duration.Hours()))
	}
	return fmt.Sprintf("%dd", int(duration.Hours()/24))
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
