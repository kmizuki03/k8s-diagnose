package app

import (
	"fmt"
	"sort"

	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func (runner *Runner) renderMetrics(snapshot *kube.Snapshot, state *model.State) {
	_, nodeTracked := snapshot.Statuses["node_metrics"]
	_, podTracked := snapshot.Statuses["pod_metrics"]
	if !nodeTracked && !podTracked {
		return
	}

	runner.Console.Chapter("リソース使用量 (上位)")
	if nodeTracked {
		runner.Console.Section("Node")
		runner.renderCommandsForKeys(snapshot, "node_metrics")
		if snapshot.Available("node_metrics") {
			rows := nodeMetricRows(snapshot)
			if len(rows) == 0 {
				runner.Console.Write("(Nodeメトリクスなし)")
			} else {
				runner.Console.Table([]string{"NAME", "CPU(cores)", "CPU%", "MEMORY(bytes)", "MEMORY%"}, rows, true)
			}
		} else {
			renderMetricUnavailable(runner, state, "K8S.METRICS.EC8CBD04", "Node使用量", snapshot.Status("node_metrics"))
		}
	}
	if podTracked {
		runner.Console.Section("Pod (CPU上位10)")
		runner.renderCommandsForKeys(snapshot, "pod_metrics")
		if snapshot.Available("pod_metrics") {
			rows := podMetricRows(snapshot.PodMetrics, 10)
			if len(rows) == 0 {
				runner.Console.Write("(Podメトリクスなし)")
			} else {
				runner.Console.Table([]string{"NAMESPACE", "NAME", "CPU(cores)", "MEMORY(bytes)"}, rows, true)
			}
		} else {
			renderMetricUnavailable(runner, state, "K8S.METRICS.D0439E88", "Pod使用量", snapshot.Status("pod_metrics"))
		}
	}
}

func renderMetricUnavailable(runner *Runner, state *model.State, code, description string, status kube.FetchStatus) {
	for _, finding := range state.Findings {
		if finding.Code == code {
			runner.Console.Flag(finding)
			return
		}
	}
	runner.Console.Write(fmt.Sprintf("  ? [メトリクス] %sを取得できませんでした。原因: %s", description, fetchStatusText(status)))
}

func fetchStatusText(status kube.FetchStatus) string {
	switch status.Status {
	case kube.StatusNotFound:
		return "Metrics APIが提供されていません (NotFound)"
	case kube.StatusUnavailable:
		return "Kubernetes APIに到達できません"
	case kube.StatusForbidden:
		return "アクセス権限がありません (RBAC)"
	case kube.StatusUnauthorized:
		return "認証が必要です"
	case kube.StatusTimeout:
		return "要求がタイムアウトしました"
	case kube.StatusInvalid:
		return "API要求が不正です"
	default:
		if status.Reason != "" {
			return status.Reason
		}
		return "Kubernetes APIでエラーが発生しました"
	}
}

func nodeMetricRows(snapshot *kube.Snapshot) []console.TableRow {
	allocatable := map[string]corev1.ResourceList{}
	for i := range snapshot.Nodes {
		allocatable[snapshot.Nodes[i].Name] = snapshot.Nodes[i].Status.Allocatable
	}
	type row struct {
		name string
		data console.TableRow
	}
	values := make([]row, 0, len(snapshot.NodeMetrics))
	for i := range snapshot.NodeMetrics {
		item := &snapshot.NodeMetrics[i]
		cpu, hasCPU := metricQuantity(item.Object, "usage", "cpu")
		memory, hasMemory := metricQuantity(item.Object, "usage", "memory")
		capacity := allocatable[item.GetName()]
		cpuCapacity, hasCPUCapacity := capacity[corev1.ResourceCPU]
		memoryCapacity, hasMemoryCapacity := capacity[corev1.ResourceMemory]
		values = append(values, row{name: item.GetName(), data: console.TableRow{Cells: []string{
			item.GetName(), quantityText(cpu, hasCPU), quantityPercent(cpu, hasCPU, cpuCapacity, hasCPUCapacity),
			quantityText(memory, hasMemory), quantityPercent(memory, hasMemory, memoryCapacity, hasMemoryCapacity),
		}}})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].name < values[j].name })
	rows := make([]console.TableRow, 0, len(values))
	for _, value := range values {
		rows = append(rows, value.data)
	}
	return rows
}

func podMetricRows(items []unstructured.Unstructured, limit int) []console.TableRow {
	type row struct {
		namespace, name string
		cpu, memory     resource.Quantity
		hasCPU, hasMem  bool
	}
	values := make([]row, 0, len(items))
	for i := range items {
		value := row{namespace: items[i].GetNamespace(), name: items[i].GetName()}
		containers, found, _ := unstructured.NestedSlice(items[i].Object, "containers")
		if found {
			for _, entry := range containers {
				container, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				if quantity, ok := metricQuantity(container, "usage", "cpu"); ok {
					value.cpu.Add(quantity)
					value.hasCPU = true
				}
				if quantity, ok := metricQuantity(container, "usage", "memory"); ok {
					value.memory.Add(quantity)
					value.hasMem = true
				}
			}
		}
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].cpu.MilliValue() != values[j].cpu.MilliValue() {
			return values[i].cpu.MilliValue() > values[j].cpu.MilliValue()
		}
		if values[i].namespace != values[j].namespace {
			return values[i].namespace < values[j].namespace
		}
		return values[i].name < values[j].name
	})
	if limit > 0 && len(values) > limit {
		values = values[:limit]
	}
	rows := make([]console.TableRow, 0, len(values))
	for _, value := range values {
		rows = append(rows, console.TableRow{Cells: []string{
			value.namespace, value.name, quantityText(value.cpu, value.hasCPU), quantityText(value.memory, value.hasMem),
		}})
	}
	return rows
}

func metricQuantity(object map[string]any, fields ...string) (resource.Quantity, bool) {
	value, found, err := unstructured.NestedString(object, fields...)
	if err != nil || !found || value == "" {
		return resource.Quantity{}, false
	}
	quantity, err := resource.ParseQuantity(value)
	return quantity, err == nil
}

func quantityText(quantity resource.Quantity, available bool) string {
	if !available {
		return "-"
	}
	return quantity.String()
}

func quantityPercent(used resource.Quantity, hasUsed bool, capacity resource.Quantity, hasCapacity bool) string {
	if !hasUsed || !hasCapacity || capacity.Sign() <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", used.AsApproximateFloat64()/capacity.AsApproximateFloat64()*100)
}
