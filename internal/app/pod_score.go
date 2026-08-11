package app

import (
	"fmt"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// calculatePodScore is deliberately different from the cluster Health score.
// Cluster Health answers "how many independent confirmed root causes exist?";
// this score answers "how usable is this one Pod right now?". The dimensions
// add up to 100 and expose exactly which part lowered the result.
func calculatePodScore(pod *corev1.Pod, state *model.State, snapshot *kube.Snapshot) model.ScopedScore {
	dimensions := []model.ScoreDimension{
		podLifecycleDimension(pod),
		podReadinessDimension(pod),
		podContainerDimension(pod),
		restartLogDimension(pod, state.Findings),
		resourceConfigDimension(pod, state.Findings, snapshot),
		schedulingNodeDimension(pod, state.Findings, snapshot),
		withDetail(findingDimension("dependencies", "依存リソース", 7, state.Findings, dependencyFinding, dimensionWeights{issue: 7, warning: 3, candidate: 1}), dependencyDetail(pod)),
		withDetail(findingDimension("storage", "Storage", 4, state.Findings, storageFinding, dimensionWeights{issue: 4, warning: 2, candidate: 1}), storageDetail(snapshot)),
		withDetail(findingDimension("probe", "Probe・接続", 6, state.Findings, probeFinding, dimensionWeights{issue: 6, warning: 3, candidate: 1}), probeDetail(pod)),
		withDetail(findingDimension("service", "Service・Endpoint", 4, state.Findings, serviceFinding, dimensionWeights{issue: 4, warning: 2, candidate: 1}), serviceDetail(snapshot)),
		withDetail(findingDimension("network-policy", "NetworkPolicy", 2, state.Findings, networkPolicyFinding, dimensionWeights{issue: 2, warning: 1, candidate: 1}), networkPolicyDetail(snapshot)),
		withDetail(findingDimension("ingress-tls", "Ingress・TLS", 4, state.Findings, ingressTLSFinding, dimensionWeights{issue: 4, warning: 2, candidate: 1}), ingressTLSDetail(snapshot)),
	}
	total, maximum := 0, 0
	for _, dimension := range dimensions {
		total += dimension.Score
		maximum += dimension.Maximum
	}
	return model.ScopedScore{
		Kind: "Pod", Resource: "Pod/" + pod.Namespace + "/" + pod.Name,
		Score: total, Maximum: maximum, Dimensions: dimensions,
	}
}

func podLifecycleDimension(pod *corev1.Pod) model.ScoreDimension {
	const maximum = 15
	score := 5
	switch pod.Status.Phase {
	case corev1.PodRunning, corev1.PodSucceeded:
		score = maximum
	case corev1.PodPending:
		score = 5
	case corev1.PodFailed:
		score = 0
	case corev1.PodUnknown:
		score = 2
	}
	if pod.DeletionTimestamp != nil {
		score = min(score, 5)
	}
	if value, known := podConditionStatus(pod, corev1.DisruptionTarget); known && value == corev1.ConditionTrue {
		score = min(score, 8)
	}
	detail := "phase: " + valueOr(string(pod.Status.Phase), "Unknown")
	if pod.DeletionTimestamp != nil {
		detail += " / 終了処理中"
	}
	return model.ScoreDimension{ID: "lifecycle", Label: "ライフサイクル", Score: score, Maximum: maximum, Detail: detail}
}

func podReadinessDimension(pod *corev1.Pod) model.ScoreDimension {
	const maximum = 15
	if pod.Status.Phase == corev1.PodSucceeded {
		return model.ScoreDimension{ID: "readiness", Label: "Ready・Condition", Score: maximum, Maximum: maximum, Detail: "正常完了"}
	}
	ready, known := podConditionStatus(pod, corev1.PodReady)
	score, label := 7, "未取得"
	if known {
		label = string(ready)
		if ready == corev1.ConditionTrue {
			score = maximum
		} else {
			score = 0
		}
	}
	if value, exists := podConditionStatus(pod, corev1.PodReadyToStartContainers); exists && value == corev1.ConditionFalse {
		score = 0
		label += " / sandbox未準備"
	}
	return model.ScoreDimension{ID: "readiness", Label: "Ready・Condition", Score: score, Maximum: maximum, Detail: "Ready: " + label}
}

func podConditionStatus(pod *corev1.Pod, conditionType corev1.PodConditionType) (corev1.ConditionStatus, bool) {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == conditionType {
			return condition.Status, true
		}
	}
	return "", false
}

func podContainerDimension(pod *corev1.Pod) model.ScoreDimension {
	const maximum = 20
	statuses := map[string]corev1.ContainerStatus{}
	for _, status := range pod.Status.InitContainerStatuses {
		statuses["init/"+status.Name] = status
	}
	for _, status := range pod.Status.ContainerStatuses {
		statuses["app/"+status.Name] = status
	}
	type activeContainer struct{ key string }
	containers := []activeContainer{}
	for _, container := range pod.Spec.InitContainers {
		if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			containers = append(containers, activeContainer{key: "init/" + container.Name})
		}
	}
	for _, container := range pod.Spec.Containers {
		containers = append(containers, activeContainer{key: "app/" + container.Name})
	}
	if len(containers) == 0 {
		return model.ScoreDimension{ID: "containers", Label: "コンテナ稼働", Score: 0, Maximum: maximum, Detail: "評価対象コンテナなし"}
	}

	unitTotal, readyCount, abnormalCount := 0, 0, 0
	for _, container := range containers {
		status, found := statuses[container.key]
		unit := 20
		if found {
			switch {
			case status.State.Running != nil && status.Ready:
				unit, readyCount = 100, readyCount+1
			case status.State.Running != nil:
				unit = 55
			case status.State.Waiting != nil:
				unit = 0
				if status.State.Waiting.Reason == "ContainerCreating" || status.State.Waiting.Reason == "PodInitializing" {
					unit = 35
				}
				abnormalCount++
			case status.State.Terminated != nil && pod.Status.Phase == corev1.PodSucceeded && status.State.Terminated.ExitCode == 0:
				unit, readyCount = 100, readyCount+1
			case status.State.Terminated != nil:
				unit, abnormalCount = 0, abnormalCount+1
			}
		}
		unitTotal += unit
	}
	score := (unitTotal*maximum + len(containers)*50) / (len(containers) * 100)
	detail := fmt.Sprintf("Ready %d/%d", readyCount, len(containers))
	if abnormalCount > 0 {
		detail += fmt.Sprintf(" / 異常状態 %d件", abnormalCount)
	}
	return model.ScoreDimension{ID: "containers", Label: "コンテナ稼働", Score: score, Maximum: maximum, Detail: detail}
}

func restartLogDimension(pod *corev1.Pod, findings []model.Finding) model.ScoreDimension {
	const maximum = 10
	penalty, restarts, logs, runtime := 0, 0, 0, 0
	unavailable := 0
	restartableInit := map[string]bool{}
	for _, container := range pod.Spec.InitContainers {
		if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			restartableInit[container.Name] = true
		}
	}
	statuses := append([]corev1.ContainerStatus{}, pod.Status.ContainerStatuses...)
	for _, status := range pod.Status.InitContainerStatuses {
		// A regular init container is expected to remain Terminated after a
		// successful run. Only restartable sidecars and failed/incomplete init
		// containers represent the Pod's current runtime health.
		if restartableInit[status.Name] || status.State.Terminated == nil || status.State.Terminated.ExitCode != 0 {
			statuses = append(statuses, status)
		}
	}
	for _, status := range statuses {
		switch {
		case status.State.Waiting != nil && status.State.Waiting.Reason != "ContainerCreating" && status.State.Waiting.Reason != "PodInitializing":
			penalty += 10
			runtime++
		case status.State.Terminated != nil && !(pod.Status.Phase == corev1.PodSucceeded && status.State.Terminated.ExitCode == 0):
			penalty += 10
			runtime++
		}
	}
	for _, finding := range findings {
		switch {
		case finding.Severity == model.Unavailable && finding.Section == "ログ":
			unavailable++
		case finding.Code == "K8S.POD.ABNORMAL_STATE" || finding.Code == "K8S.POD.FAILED_PHASE":
			// Pod health rules describe the same current container state that was
			// inspected above. Keep the Finding as evidence, but do not subtract
			// twice for one CrashLoop/termination.
			if runtime == 0 {
				penalty += 10
				runtime++
			}
		case finding.Code == "K8S.POD.PREVIOUS_OOM_KILLED":
			penalty += 6
			restarts++
		case finding.Code == "K8S.POD.RECENT_RESTARTS":
			penalty += 4
			restarts++
		case finding.Code == "K8S.POD.NON_RUNNING_STATE" || finding.Code == "K8S.POD.JOB_ATTEMPT_FAILED":
			penalty += 4
			runtime++
		case strings.HasPrefix(finding.Code, "K8S.LOG.") && finding.Severity == model.Warning:
			penalty += 4
			logs++
		case strings.HasPrefix(finding.Code, "K8S.LOG.") && finding.Severity == model.Candidate:
			penalty += 2
			logs++
		}
	}
	parts := []string{}
	if runtime > 0 {
		parts = append(parts, fmt.Sprintf("実行異常 %d件", runtime))
	}
	if restarts > 0 {
		parts = append(parts, fmt.Sprintf("再起動・OOM %d件", restarts))
	}
	if logs > 0 {
		parts = append(parts, fmt.Sprintf("ログ署名 %d件", logs))
	}
	if unavailable > 0 {
		parts = append(parts, fmt.Sprintf("ログ確認不能 %d件", unavailable))
	}
	if len(parts) == 0 {
		parts = append(parts, "直近異常所見なし")
	}
	return model.ScoreDimension{ID: "restart-log", Label: "再起動・ログ", Score: max(0, maximum-penalty), Maximum: maximum, Detail: strings.Join(parts, " / ")}
}

func resourceConfigDimension(pod *corev1.Pod, findings []model.Finding, snapshot *kube.Snapshot) model.ScoreDimension {
	dimension := findingDimension("resources", "Resources・構成", 5, findings, resourceFinding, dimensionWeights{issue: 5, warning: 3, candidate: 1})
	penalty, detail := memoryLimitPressure(pod, snapshot)
	dimension.Score = max(0, dimension.Score-penalty)
	return withDetail(dimension, detail)
}

func memoryLimitPressure(pod *corev1.Pod, snapshot *kube.Snapshot) (int, string) {
	if snapshot == nil {
		return 0, "メトリクス未取得"
	}
	if status, tracked := snapshot.Statuses["pod_metrics"]; tracked && !status.Available {
		return 0, "メトリクスを確認できません"
	}
	if len(snapshot.PodMetrics) == 0 {
		return 0, "メトリクスデータなし"
	}
	limits := map[string]int64{}
	podLevelLimit := int64(0)
	if pod.Spec.Resources != nil {
		if limit := pod.Spec.Resources.Limits.Memory(); limit != nil {
			podLevelLimit = limit.Value()
		}
	}
	for _, container := range pod.Spec.InitContainers {
		if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			if limit := container.Resources.Limits.Memory(); limit != nil {
				limits[container.Name] = limit.Value()
			}
		}
	}
	for _, container := range pod.Spec.Containers {
		if limit := container.Resources.Limits.Memory(); limit != nil {
			limits[container.Name] = limit.Value()
		}
	}
	maximumRatio, totalUsage := int64(-1), int64(0)
	for i := range snapshot.PodMetrics {
		containers, found, _ := unstructured.NestedSlice(snapshot.PodMetrics[i].Object, "containers")
		if !found {
			continue
		}
		for _, raw := range containers {
			container, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name, _ := container["name"].(string)
			limit := limits[name]
			usage, ok := metricQuantity(container, "usage", "memory")
			if !ok {
				continue
			}
			totalUsage += usage.Value()
			if podLevelLimit <= 0 && limit > 0 {
				ratio := usage.Value() * 100 / limit
				maximumRatio = max(maximumRatio, ratio)
			}
		}
	}
	if podLevelLimit > 0 {
		maximumRatio = totalUsage * 100 / podLevelLimit
	}
	if maximumRatio < 0 {
		return 0, "メモリ上限に対する使用率は算出対象なし"
	}
	penalty := 0
	switch {
	case maximumRatio >= 100:
		penalty = 5
	case maximumRatio >= 90:
		penalty = 3
	case maximumRatio >= 75:
		penalty = 1
	}
	return penalty, fmt.Sprintf("メモリ上限に対する最大使用率 %d%%", maximumRatio)
}

func schedulingNodeDimension(pod *corev1.Pod, findings []model.Finding, snapshot *kube.Snapshot) model.ScoreDimension {
	dimension := findingDimension("scheduling", "Scheduling・Node", 8, findings, schedulingFinding, dimensionWeights{issue: 8, warning: 4, candidate: 2})
	if snapshot == nil || pod.Spec.NodeName == "" {
		return withDetail(dimension, "Node未配置")
	}
	for i := range snapshot.Nodes {
		node := &snapshot.Nodes[i]
		if node.Name != pod.Spec.NodeName {
			continue
		}
		ready := "未取得"
		for _, condition := range node.Status.Conditions {
			if condition.Type != corev1.NodeReady {
				continue
			}
			ready = string(condition.Status)
			if condition.Status == corev1.ConditionFalse {
				dimension.Score = min(dimension.Score, 2)
			} else if condition.Status == corev1.ConditionUnknown {
				dimension.Score = min(dimension.Score, 3)
			}
			break
		}
		detail := fmt.Sprintf("Node=%s / Ready=%s", node.Name, ready)
		if node.Spec.Unschedulable {
			detail += " / cordon済み（稼働中Podは減点なし）"
		}
		return withDetail(dimension, detail)
	}
	return withDetail(dimension, "配置Nodeの情報なし")
}

type dimensionWeights struct{ issue, warning, candidate int }

func findingDimension(id, label string, maximum int, findings []model.Finding, matches func(model.Finding) bool, weights dimensionWeights) model.ScoreDimension {
	penalty, issues, warnings, candidates, unavailable := 0, 0, 0, 0, 0
	for _, finding := range findings {
		if !matches(finding) {
			continue
		}
		switch finding.Severity {
		case model.Issue:
			penalty += weights.issue
			issues++
		case model.Warning:
			penalty += weights.warning
			warnings++
		case model.Candidate:
			penalty += weights.candidate
			candidates++
		case model.Unavailable:
			unavailable++
		}
	}
	parts := []string{}
	if issues > 0 {
		parts = append(parts, fmt.Sprintf("確定異常 %d件", issues))
	}
	if warnings > 0 {
		parts = append(parts, fmt.Sprintf("警告 %d件", warnings))
	}
	if candidates > 0 {
		parts = append(parts, fmt.Sprintf("候補 %d件", candidates))
	}
	if unavailable > 0 {
		parts = append(parts, fmt.Sprintf("確認不能 %d件", unavailable))
	}
	if len(parts) == 0 {
		parts = append(parts, "異常所見なし")
	}
	return model.ScoreDimension{ID: id, Label: label, Score: max(0, maximum-penalty), Maximum: maximum, Detail: strings.Join(parts, " / ")}
}

func withDetail(dimension model.ScoreDimension, detail string) model.ScoreDimension {
	if detail == "" {
		return dimension
	}
	if dimension.Detail == "" {
		dimension.Detail = detail
	} else {
		dimension.Detail += " / " + detail
	}
	return dimension
}

func resourceFinding(finding model.Finding) bool {
	return finding.Section == "構成リスク" || finding.Section == "LimitRange" || finding.Section == "メトリクス" ||
		strings.HasPrefix(finding.Code, "K8S.CONFIG.") || strings.HasPrefix(finding.Code, "K8S.LIMIT_RANGE.") || strings.HasPrefix(finding.Code, "K8S.METRICS.")
}

func schedulingFinding(finding model.Finding) bool {
	return finding.Section == "Scheduling" || strings.HasPrefix(finding.Code, "K8S.SCHEDULING.")
}

func dependencyFinding(finding model.Finding) bool {
	return finding.Section == "関連リソース" || strings.HasPrefix(finding.Code, "K8S.DEPENDENCY.")
}

func storageFinding(finding model.Finding) bool {
	return finding.Section == "PVC" || finding.Section == "PV" || strings.HasPrefix(finding.Code, "K8S.PVC.") || strings.HasPrefix(finding.Code, "K8S.PV.")
}

func probeFinding(finding model.Finding) bool {
	return finding.Section == "Probe" || finding.Section == "Probe確認" || finding.Section == "接続確認" ||
		strings.HasPrefix(finding.Code, "K8S.PROBE.") || strings.HasPrefix(finding.Code, "K8S.CONNECT.")
}

func serviceFinding(finding model.Finding) bool {
	return finding.Section == "Service" || strings.HasPrefix(finding.Code, "K8S.SERVICE.")
}

func networkPolicyFinding(finding model.Finding) bool {
	return finding.Section == "NetworkPolicy" || strings.HasPrefix(finding.Code, "K8S.NETWORK_POLICY.")
}

func ingressTLSFinding(finding model.Finding) bool {
	return finding.Section == "Ingress" || finding.Section == "TLS" || strings.HasPrefix(finding.Code, "K8S.INGRESS.") || strings.HasPrefix(finding.Code, "K8S.TLS.")
}

func dependencyDetail(pod *corev1.Pod) string {
	configMaps, secrets := selectedPodObjectReferences(pod)
	return fmt.Sprintf("参照先: ConfigMap %d件 / Secret %d件 / ServiceAccount 1件", len(configMaps), len(secrets))
}

func storageDetail(snapshot *kube.Snapshot) string {
	if snapshot == nil {
		return "対象情報なし"
	}
	return fmt.Sprintf("関連PVC %d件 / PV %d件", len(snapshot.PersistentVolumeClaims), len(snapshot.PersistentVolumes))
}

func probeDetail(pod *corev1.Pod) string {
	count := 0
	visit := func(container corev1.Container) {
		for _, probe := range []*corev1.Probe{container.ReadinessProbe, container.LivenessProbe, container.StartupProbe} {
			if probe != nil {
				count++
			}
		}
	}
	for _, container := range pod.Spec.InitContainers {
		if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			visit(container)
		}
	}
	for _, container := range pod.Spec.Containers {
		visit(container)
	}
	return fmt.Sprintf("設定済みProbe %d件", count)
}

func serviceDetail(snapshot *kube.Snapshot) string {
	if snapshot == nil {
		return "対象情報なし"
	}
	ready := 0
	for _, slice := range snapshot.EndpointSlices {
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready {
				ready++
			}
		}
	}
	return fmt.Sprintf("関連Service %d件 / Ready Endpoint %d件", len(snapshot.Services), ready)
}

func networkPolicyDetail(snapshot *kube.Snapshot) string {
	if snapshot == nil {
		return "対象情報なし"
	}
	return fmt.Sprintf("このPodを選択するNetworkPolicy %d件", len(snapshot.NetworkPolicies))
}

func ingressTLSDetail(snapshot *kube.Snapshot) string {
	if snapshot == nil {
		return "対象情報なし"
	}
	tlsSecrets := 0
	for _, secret := range snapshot.Secrets {
		if secret.Type == corev1.SecretTypeTLS || len(secret.TLSCert) > 0 {
			tlsSecrets++
		}
	}
	return fmt.Sprintf("関連Ingress %d件 / TLS証明書Secret %d件", len(snapshot.Ingresses), tlsSecrets)
}
