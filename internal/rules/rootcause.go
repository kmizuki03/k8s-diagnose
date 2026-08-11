package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
)

type graphEdge struct {
	To       string
	Relation string
	Key      string
}

type dependencyGraph struct {
	forward map[string][]graphEdge
}

func newDependencyGraph() *dependencyGraph {
	return &dependencyGraph{forward: map[string][]graphEdge{}}
}

func (g *dependencyGraph) add(from, to, relation, key string) {
	if from == "" || to == "" || from == to {
		return
	}
	for _, edge := range g.forward[from] {
		if edge.To == to && edge.Relation == relation && edge.Key == key {
			return
		}
	}
	g.forward[from] = append(g.forward[from], graphEdge{To: to, Relation: relation, Key: key})
}

type graphPath struct {
	Resource  string
	Path      []string
	Relations []string
}

func (g *dependencyGraph) descendants(start, requiredKey string) []graphPath {
	result := []graphPath{}
	type queueItem struct {
		resource  string
		path      []string
		relations []string
	}
	queue := []queueItem{{start, []string{start}, nil}}
	bestDepth := map[string]int{start: 0}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		edges := append([]graphEdge{}, g.forward[current.resource]...)
		sort.Slice(edges, func(i, j int) bool { return edges[i].To+edges[i].Relation < edges[j].To+edges[j].Relation })
		for _, edge := range edges {
			if len(current.path) == 1 && requiredKey != "" && edge.Key != "" && edge.Key != requiredKey {
				continue
			}
			depth := len(current.path)
			if previous, ok := bestDepth[edge.To]; ok && previous <= depth {
				continue
			}
			bestDepth[edge.To] = depth
			path := append(append([]string{}, current.path...), edge.To)
			relations := append(append([]string{}, current.relations...), edge.Relation)
			result = append(result, graphPath{edge.To, path, relations})
			queue = append(queue, queueItem{edge.To, path, relations})
		}
	}
	return result
}

// BaselineWorkloadResolver maps a finding to stable owning workloads using the
// complete dependency graph, including healthy intermediate resources. This
// lets workload-scoped acknowledgements survive generated Pod/ReplicaSet names
// without requiring those controllers to be degraded Root Cause impacts.
func BaselineWorkloadResolver(snapshot *kube.Snapshot) func(model.Finding) []string {
	if snapshot == nil {
		snapshot = &kube.Snapshot{}
	}
	graph := buildDependencyGraph(snapshot)
	cache := map[string][]string{}
	return func(finding model.Finding) []string {
		if finding.Resource == "" {
			return nil
		}
		if cached, exists := cache[finding.Resource]; exists {
			return append([]string{}, cached...)
		}
		resources := []string{finding.Resource}
		for _, path := range graph.descendants(finding.Resource, "") {
			resources = append(resources, path.Resource)
		}
		topLevel, replicaSets := []string{}, []string{}
		for _, resource := range resources {
			switch kind := resourceKind(resource); {
			case isTopLevelController(kind):
				topLevel = append(topLevel, resource)
			case kind == "ReplicaSet":
				replicaSets = append(replicaSets, resource)
			}
		}
		result := uniqueResourceRefs(replicaSets)
		if len(topLevel) > 0 {
			result = outermostWorkloads(graph, uniqueResourceRefs(topLevel))
		}
		cache[finding.Resource] = result
		return append([]string{}, result...)
	}
}

func outermostWorkloads(graph *dependencyGraph, values []string) []string {
	candidates := map[string]struct{}{}
	for _, value := range values {
		candidates[value] = struct{}{}
	}
	result := []string{}
	for _, value := range values {
		ownedByAnotherWorkload := false
		for _, path := range graph.descendants(value, "") {
			if _, exists := candidates[path.Resource]; exists {
				ownedByAnotherWorkload = true
				break
			}
		}
		if !ownedByAnotherWorkload {
			result = append(result, value)
		}
	}
	return uniqueResourceRefs(result)
}

func isTopLevelController(kind string) bool {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
		return true
	default:
		return false
	}
}

func uniqueResourceRefs(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// Correlate converts flat findings into a cause/evidence/blast-radius model.
// The State keeps both views so text and machine-readable reports share one
// correlation result.
func Correlate(snapshot *kube.Snapshot, state *model.State) {
	graph := buildDependencyGraph(snapshot)
	byResource := map[string][]model.Finding{}
	findingsByID := map[string]model.Finding{}
	for _, finding := range state.Findings {
		findingsByID[finding.ID] = finding
		if finding.Resource != "" {
			byResource[finding.Resource] = append(byResource[finding.Resource], finding)
		}
	}
	roots := []model.RootCause{}
	candidates := []model.Finding{}
	for _, finding := range state.Findings {
		if rootEligible(finding) {
			candidates = append(candidates, finding)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := rootPriority(candidates[i]), rootPriority(candidates[j])
		if left != right {
			return left < right
		}
		if candidates[i].Confidence != candidates[j].Confidence {
			return candidates[i].Confidence > candidates[j].Confidence
		}
		return candidates[i].ID < candidates[j].ID
	})
	claimed := map[string]struct{}{}
	for _, cause := range candidates {
		if _, exists := claimed[cause.ID]; exists {
			continue
		}
		requiredKey := ""
		if cause.Code == "K8S.DEPENDENCY.MISSING_KEY" {
			parts := strings.Split(cause.StableKey, "/")
			if len(parts) > 1 {
				requiredKey = parts[len(parts)-1]
			}
		}
		paths := graph.descendants(cause.Resource, requiredKey)
		direct, propagated := []model.Impact{}, []model.Impact{}
		related := []string{}
		rootEvidence := append([]model.Evidence{}, cause.Evidence...)
		for _, supporting := range byResource[cause.Resource] {
			if supporting.ID == cause.ID || !strings.HasPrefix(supporting.Code, "K8S.LOG.") {
				continue
			}
			rootEvidence = appendLogEvidence(rootEvidence, supporting)
			related = append(related, supporting.ID)
		}
		for _, path := range paths {
			values := []model.Finding{}
			for _, value := range byResource[path.Resource] {
				if value.Severity == model.Issue || value.Severity == model.Warning {
					values = append(values, value)
				}
			}
			// A graph edge only proves dependency, not degradation. Healthy
			// resources stay in Path as intermediates. A resource becomes an
			// impact only through a warning/issue or its typed degraded status.
			message := ""
			if len(values) > 0 {
				message = values[0].Message
			} else {
				message, _ = degradedResourceMessage(snapshot, path.Resource)
			}
			if message == "" {
				continue
			}
			findingIDs := []string{}
			for _, value := range values {
				findingIDs = append(findingIDs, value.ID)
				related = append(related, value.ID)
				if strings.HasPrefix(value.Code, "K8S.LOG.") {
					rootEvidence = appendLogEvidence(rootEvidence, value)
				}
			}
			impact := model.Impact{
				Resource: path.Resource, Kind: resourceKind(path.Resource), Message: message,
				Depth: len(path.Path) - 1, FindingIDs: findingIDs, Path: path.Path, PathRelations: path.Relations,
			}
			if len(path.Relations) > 0 {
				impact.Relation = path.Relations[len(path.Relations)-1]
			}
			if impact.Depth == 1 {
				direct = append(direct, impact)
			} else {
				propagated = append(propagated, impact)
			}
		}
		confidence := cause.Confidence
		if symptomCode(cause.Code) && confidence > 70 {
			confidence = 70
		}
		root := model.NewRootCause(
			cause, confidence, rootEvidence, direct, propagated,
			remediations(cause), confirmationCommands(cause), related,
		)
		roots = append(roots, root)
		for _, id := range root.RelatedFindingIDs {
			finding, exists := findingsByID[id]
			if !exists || finding.Severity != model.Issue {
				continue
			}
			if id == cause.ID || !strongRootCode(finding.Code) {
				claimed[id] = struct{}{}
			}
		}
	}
	sort.SliceStable(roots, func(i, j int) bool {
		if roots[i].Confirmed != roots[j].Confirmed {
			return roots[i].Confirmed
		}
		if roots[i].Confidence != roots[j].Confidence {
			return roots[i].Confidence > roots[j].Confidence
		}
		return roots[i].Cause.Resource < roots[j].Cause.Resource
	})
	state.SetRootCauses(roots)
}

func appendLogEvidence(evidence []model.Evidence, finding model.Finding) []model.Evidence {
	evidence = append(evidence, model.Evidence{Kind: "log-signature", Key: finding.Code, Value: finding.Message})
	for _, item := range finding.Evidence {
		if item.Kind == "log" && item.Key == "match" {
			evidence = append(evidence, item)
		}
	}
	return evidence
}

func degradedResourceMessage(snapshot *kube.Snapshot, resource string) (string, bool) {
	parts := strings.Split(resource, "/")
	kind := parts[0]
	namespace, name := "", ""
	if len(parts) == 3 {
		namespace, name = parts[1], parts[2]
	} else if len(parts) == 2 {
		name = parts[1]
	} else {
		return "", false
	}
	switch kind {
	case "Pod":
		for i := range snapshot.Pods {
			pod := &snapshot.Pods[i]
			if pod.Namespace != namespace || pod.Name != name {
				continue
			}
			ready := condition(pod.Status.Conditions, corev1.PodReady)
			if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodPending || pod.Status.Phase == corev1.PodRunning && ready != nil && ready.Status != corev1.ConditionTrue {
				return fmt.Sprintf("Pod %s: phase=%s / Ready未達", shortRef(namespace, name), pod.Status.Phase), true
			}
		}
	case "ReplicaSet":
		for i := range snapshot.ReplicaSets {
			item := &snapshot.ReplicaSets[i]
			if item.Namespace == namespace && item.Name == name && statusGenerationCurrent(item.Generation, item.Status.ObservedGeneration) {
				desired := int32Value(item.Spec.Replicas, 1)
				if desired > 0 && item.Status.ReadyReplicas < desired {
					return fmt.Sprintf("ReplicaSet %s: Ready %d/%d", shortRef(namespace, name), item.Status.ReadyReplicas, desired), true
				}
			}
		}
	case "Deployment":
		for i := range snapshot.Deployments {
			item := &snapshot.Deployments[i]
			if item.Namespace == namespace && item.Name == name && statusGenerationCurrent(item.Generation, item.Status.ObservedGeneration) {
				desired := int32Value(item.Spec.Replicas, 1)
				if desired > 0 && item.Status.ReadyReplicas < desired {
					return fmt.Sprintf("Deployment %s: Ready %d/%d", shortRef(namespace, name), item.Status.ReadyReplicas, desired), true
				}
			}
		}
	case "StatefulSet":
		for i := range snapshot.StatefulSets {
			item := &snapshot.StatefulSets[i]
			if item.Namespace == namespace && item.Name == name && statusGenerationCurrent(item.Generation, item.Status.ObservedGeneration) {
				desired := int32Value(item.Spec.Replicas, 1)
				if desired > 0 && item.Status.ReadyReplicas < desired {
					return fmt.Sprintf("StatefulSet %s: Ready %d/%d", shortRef(namespace, name), item.Status.ReadyReplicas, desired), true
				}
			}
		}
	case "DaemonSet":
		for i := range snapshot.DaemonSets {
			item := &snapshot.DaemonSets[i]
			if item.Namespace == namespace && item.Name == name && statusGenerationCurrent(item.Generation, item.Status.ObservedGeneration) && item.Status.DesiredNumberScheduled > 0 && item.Status.NumberReady < item.Status.DesiredNumberScheduled {
				return fmt.Sprintf("DaemonSet %s: Ready %d/%d", shortRef(namespace, name), item.Status.NumberReady, item.Status.DesiredNumberScheduled), true
			}
		}
	case "EndpointSlice":
		for i := range snapshot.EndpointSlices {
			item := &snapshot.EndpointSlices[i]
			if item.Namespace != namespace || item.Name != name {
				continue
			}
			ready := 0
			for _, endpoint := range item.Endpoints {
				isReady := endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready
				if isReady {
					ready++
				}
			}
			if ready < len(item.Endpoints) || len(item.Endpoints) == 0 {
				return fmt.Sprintf("EndpointSlice %s: Ready Endpoint %d/%d", shortRef(namespace, name), ready, len(item.Endpoints)), true
			}
		}
	case "Service":
		for i := range snapshot.Services {
			item := &snapshot.Services[i]
			if item.Namespace == namespace && item.Name == name && item.Spec.Type != corev1.ServiceTypeExternalName && len(item.Spec.Selector) > 0 {
				ready, fallback := serviceEndpointCounts(item, snapshot)
				if ready == 0 && fallback == 0 && len(selectedPods(item, snapshot.Pods)) > 0 {
					return fmt.Sprintf("Service %s: Ready Endpoint 0件", shortRef(namespace, name)), true
				}
				if ready == 0 && fallback > 0 {
					return fmt.Sprintf("Service %s: 終了中serving Endpoint %d件だけ", shortRef(namespace, name), fallback), true
				}
			}
		}
	}
	return "", false
}

func rootPriority(finding model.Finding) int {
	if strings.HasPrefix(finding.Code, "K8S.DEPENDENCY.") {
		return 0
	}
	if strongRootCode(finding.Code) {
		return 1
	}
	return 2
}

func strongRootCode(code string) bool {
	switch code {
	case "K8S.DEPENDENCY.MISSING_OBJECT", "K8S.DEPENDENCY.MISSING_KEY",
		"K8S.NODE.CONDITION", "K8S.PVC.NOT_BOUND", "K8S.PVC.LOST", "K8S.PVC.STORAGE_CLASS_NOT_FOUND",
		"K8S.PV.FAILED",
		"K8S.TLS.CERT_EXPIRED", "K8S.TLS.CERT_INVALID", "K8S.TLS.KEY_PAIR_INVALID", "K8S.CONTROL_PLANE.READYZ_FAILED",
		"K8S.INGRESS.MISSING_REFERENCE", "K8S.WEBHOOK.MISSING_SERVICE",
		"K8S.SERVICE.TARGET_PORT_UNRESOLVED", "K8S.PROBE.PORT_UNRESOLVED",
		"K8S.WORKLOAD.PROGRESS_DEADLINE_EXCEEDED", "K8S.WORKLOAD.REPLICA_FAILURE",
		"K8S.SCHEDULING.NO_AVAILABLE_NODE", "K8S.SCHEDULING.NODE_AFFINITY_MISMATCH",
		"K8S.SCHEDULING.UNTOLERATED_TAINT", "K8S.SCHEDULING.INSUFFICIENT_RESOURCES":
		return true
	default:
		return false
	}
}

func symptomCode(code string) bool {
	switch code {
	case "K8S.POD.ABNORMAL_STATE", "K8S.POD.PENDING_STATE", "K8S.POD.NOT_READY",
		"K8S.POD.FAILED_PHASE",
		"K8S.WORKLOAD.REPLICAS_UNAVAILABLE", "K8S.SERVICE.NO_READY_ENDPOINT", "K8S.SERVICE.TERMINATING_ENDPOINTS_ONLY":
		return true
	default:
		return strings.HasPrefix(code, "K8S.CONNECT.")
	}
}

func rootEligible(finding model.Finding) bool {
	if finding.Severity == model.Issue {
		return true
	}
	if finding.Severity != model.Warning {
		return false
	}
	prefixes := []string{"K8S.SCHEDULING.", "K8S.NODE.", "K8S.PVC.", "K8S.WORKLOAD.ROLLOUT", "K8S.WORKLOAD.REPLICA_FAILURE", "K8S.POD.SANDBOX", "K8S.PROBE.", "K8S.CONNECT."}
	for _, prefix := range prefixes {
		if strings.HasPrefix(finding.Code, prefix) {
			return true
		}
	}
	return false
}

func buildDependencyGraph(snapshot *kube.Snapshot) *dependencyGraph {
	graph := newDependencyGraph()
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		podRef := ref("Pod", pod.Namespace, pod.Name)
		forEachPodProbe(pod, func(container corev1.Container, probeType string, _ *corev1.Probe) {
			graph.add(probeResource(pod.Namespace, pod.Name, container.Name, probeType), podRef, "probe-controls", "")
		})
		for _, dependency := range podDependencies(pod) {
			if dependency.Optional || strings.HasPrefix(dependency.Source, "ephemeralContainer/") {
				continue
			}
			graph.add(ref(dependency.Kind, dependency.Namespace, dependency.Name), podRef, "required-by-pod", dependency.Key)
		}
		for _, dependency := range podPVCReferences(pod) {
			if dependency.ephemeral {
				graph.add(ref("PersistentVolumeClaim", pod.Namespace, dependency.claimName), podRef, "generic-ephemeral-volume", "")
			}
		}
		if owner := ownerRef(pod.ObjectMeta); owner != nil {
			graph.add(podRef, ref(owner.Kind, pod.Namespace, owner.Name), "workload-member", "")
		}
		if pod.Spec.NodeName != "" {
			graph.add(ref("Node", "", pod.Spec.NodeName), podRef, "scheduled-pod", "")
		}
	}
	for i := range snapshot.ReplicaSets {
		rs := &snapshot.ReplicaSets[i]
		if owner := ownerRef(rs.ObjectMeta); owner != nil {
			graph.add(ref("ReplicaSet", rs.Namespace, rs.Name), ref(owner.Kind, rs.Namespace, owner.Name), "owned-workload", "")
		}
	}
	for i := range snapshot.Jobs {
		job := &snapshot.Jobs[i]
		if owner := ownerRef(job.ObjectMeta); owner != nil && owner.Kind == "CronJob" {
			graph.add(ref("Job", job.Namespace, job.Name), ref("CronJob", job.Namespace, owner.Name), "owned-workload", "")
		}
	}
	for i := range snapshot.PersistentVolumeClaims {
		claim := &snapshot.PersistentVolumeClaims[i]
		if claim.Spec.VolumeName != "" {
			graph.add(ref("PersistentVolume", "", claim.Spec.VolumeName), ref("PersistentVolumeClaim", claim.Namespace, claim.Name), "volume-binding", "")
		}
	}
	for i := range snapshot.EndpointSlices {
		slice := &snapshot.EndpointSlices[i]
		sliceRef := ref("EndpointSlice", slice.Namespace, slice.Name)
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef != nil && endpoint.TargetRef.Kind == "Pod" {
				graph.add(ref("Pod", slice.Namespace, endpoint.TargetRef.Name), sliceRef, "endpoint-registration", "")
			}
		}
		if service := slice.Labels["kubernetes.io/service-name"]; service != "" {
			graph.add(sliceRef, ref("Service", slice.Namespace, service), "service-endpoints", "")
		}
	}
	for i := range snapshot.Services {
		service := &snapshot.Services[i]
		serviceRef := ref("Service", service.Namespace, service.Name)
		for podIndex := range snapshot.Pods {
			pod := &snapshot.Pods[podIndex]
			if serviceMatchesPod(service, pod) {
				graph.add(ref("Pod", pod.Namespace, pod.Name), serviceRef, "service-selector", "")
			}
		}
	}
	for i := range snapshot.Ingresses {
		ingress := &snapshot.Ingresses[i]
		ingressRef := ref("Ingress", ingress.Namespace, ingress.Name)
		if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
			graph.add(ref("Service", ingress.Namespace, ingress.Spec.DefaultBackend.Service.Name), ingressRef, "ingress-backend", "")
		}
		for _, rule := range ingress.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil {
					graph.add(ref("Service", ingress.Namespace, path.Backend.Service.Name), ingressRef, "ingress-backend", "")
				}
			}
		}
		for _, tls := range ingress.Spec.TLS {
			if tls.SecretName != "" {
				graph.add(ref("Secret", ingress.Namespace, tls.SecretName), ingressRef, "ingress-tls", "")
			}
		}
	}
	for i := range snapshot.ValidatingWebhooks {
		item := &snapshot.ValidatingWebhooks[i]
		for _, webhook := range item.Webhooks {
			if webhook.ClientConfig.Service != nil {
				service := webhook.ClientConfig.Service
				graph.add(ref("Service", service.Namespace, service.Name), ref("ValidatingWebhookConfiguration", "", item.Name), "webhook-client", "")
			}
		}
	}
	for i := range snapshot.MutatingWebhooks {
		item := &snapshot.MutatingWebhooks[i]
		for _, webhook := range item.Webhooks {
			if webhook.ClientConfig.Service != nil {
				service := webhook.ClientConfig.Service
				graph.add(ref("Service", service.Namespace, service.Name), ref("MutatingWebhookConfiguration", "", item.Name), "webhook-client", "")
			}
		}
	}
	return graph
}

func resourceKind(resource string) string {
	if index := strings.Index(resource, "/"); index >= 0 {
		return resource[:index]
	}
	return resource
}

func remediations(finding model.Finding) []string {
	if strings.HasPrefix(finding.Code, "K8S.PROBE.") {
		switch finding.Reason {
		case "readinessProbe":
			return []string{"readinessProbeのpath、port、scheme、timeoutSecondsと認証headerを確認する", "アプリのReady条件が満たされる時刻とinitialDelaySecondsを比較する"}
		case "livenessProbe":
			return []string{"livenessProbeのpath、port、timeoutSecondsを確認し、正常起動に必要な時間より厳しすぎないか見直す"}
		case "startupProbe":
			return []string{"startupProbeのfailureThreshold×periodSecondsが最大起動時間を十分に覆うか確認する"}
		case "NamedPortUnresolved":
			return []string{"Probeのport名を同じcontainerのports[].nameに合わせるか、有効な数値portへ修正する"}
		}
		return []string{"Probeのhandler、port、pathと閾値をPod定義およびアプリの待受設定に合わせる"}
	}
	switch finding.Code {
	case "K8S.DEPENDENCY.MISSING_OBJECT":
		return []string{"必須参照先を作成するか、Pod/Workloadの参照名を修正する"}
	case "K8S.DEPENDENCY.MISSING_KEY":
		return []string{"Secret/ConfigMapに必要なキーを追加するか、keyRefを修正する"}
	case "K8S.SERVICE.TARGET_PORT_UNRESOLVED":
		return []string{"Serviceのspec.ports[].targetPortを、selectorで選ばれるPodのports[].nameに合わせる"}
	case "K8S.WORKLOAD.PROGRESS_DEADLINE_EXCEEDED":
		return []string{"Deployment conditionとReplicaSet Eventを確認し、停滞したrolloutの設定またはimageを修正する"}
	case "K8S.WORKLOAD.REPLICA_FAILURE":
		return []string{"ReplicaFailure messageにあるQuota、Admission、PVCの拒否原因を修正する"}
	case "K8S.SCHEDULING.INSUFFICIENT_RESOURCES":
		return []string{"Pod requestsの見直し、Node容量の追加、または不要Podの整理を検討する"}
	case "K8S.SCHEDULING.UNTOLERATED_TAINT":
		return []string{"Node taintとPod tolerationの意図を確認し、必要な場合だけtolerationを追加する"}
	case "K8S.POD.ABNORMAL_STATE":
		return []string{"containerの現在/前回ログとEventを確認する", "Probe失敗がある場合はpath、port、timeoutSecondsを確認する"}
	case "K8S.TLS.CERT_EXPIRED":
		return []string{"TLS Secretの証明書を更新し、Ingress/consumerが新しいSecretを読み込んだことを確認する"}
	case "K8S.TLS.CERT_INVALID":
		return []string{"TLS Secretのtls.crtを有効なPEM形式のX.509証明書へ置き換える"}
	case "K8S.TLS.KEY_PAIR_INVALID":
		return []string{"TLS Secretのtls.crtに対応するPEM秘密鍵をtls.keyへ設定する"}
	case "K8S.PVC.STORAGE_CLASS_NOT_FOUND":
		return []string{"PVCのstorageClassNameを既存のStorageClassへ修正するか、必要なStorageClassを作成する"}
	case "K8S.PV.FAILED":
		return []string{"PVのstatus.message、CSI/volume pluginのEventとストレージ基盤を確認する"}
	default:
		return nil
	}
}

func confirmationCommands(finding model.Finding) []string {
	parts := strings.Split(finding.Resource, "/")
	if len(parts) == 2 && parts[0] == "ControlPlane" {
		switch parts[1] {
		case "readyz", "livez":
			return []string{fmt.Sprintf("kubectl get --raw='/%s?verbose'", parts[1])}
		}
	}
	if len(parts) == 5 && parts[0] == "Probe" {
		return []string{
			fmt.Sprintf("kubectl get pod %s -n %s -o yaml", parts[2], parts[1]),
			fmt.Sprintf("kubectl describe pod %s -n %s", parts[2], parts[1]),
		}
	}
	if len(parts) == 3 {
		if parts[0] == "Secret" {
			// describe lists key names and byte sizes without printing data.
			return []string{fmt.Sprintf("kubectl describe secret %s -n %s", parts[2], parts[1])}
		}
		return []string{fmt.Sprintf("kubectl get %s %s -n %s -o yaml", strings.ToLower(parts[0]), parts[2], parts[1])}
	}
	if len(parts) == 2 {
		return []string{fmt.Sprintf("kubectl get %s %s -o yaml", strings.ToLower(parts[0]), parts[1])}
	}
	return nil
}
