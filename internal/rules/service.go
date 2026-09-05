package rules

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	intstrutil "k8s.io/apimachinery/pkg/util/intstr"
)

type ServiceRule struct{}

func (ServiceRule) Metadata() Metadata {
	permissions := namespaced("", "services,pods,endpoints")
	permissions = append(permissions, namespaced("discovery.k8s.io", "endpointslices")...)
	return Metadata{
		ID: "services", Section: "Service", Description: "ServiceのPod選択条件・Endpoint・targetPort",
		Required:    []string{"services"},
		Optional:    []string{"pods", "endpoint_slices", "endpoints", "replicasets", "deployments", "statefulsets", "daemonsets"},
		Permissions: permissions, Modes: []string{"all", "triage", "select"},
	}
}

func (ServiceRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	// A selected-Pod snapshot intentionally narrows Pods to one item, but keeps
	// AllPods for rules that need cluster context. Dependency Services retained
	// in that snapshot may select other Pods, so evaluating their selectors
	// against the narrowed slice would report a false "no matching Pods" warning.
	selectorPods := snapshot.Pods
	if len(snapshot.AllPods) > 0 && snapshot.AvailableOrUntracked("all_pods") {
		selectorPods = snapshot.AllPods
	}
	podIndex := indexPodsByNamespace(selectorPods)
	owners := newWorkloadOwners(snapshot)
	for i := range snapshot.Services {
		service := &snapshot.Services[i]
		if service.Spec.Type == corev1.ServiceTypeExternalName {
			if finding, ok := externalNameTargetFinding(service, snapshot); ok {
				result = append(result, finding)
			}
			continue
		}
		if len(service.Spec.Selector) == 0 {
			continue
		}
		resource := ref("Service", service.Namespace, service.Name)
		pods := podIndex.selected(service)
		if service.Spec.InternalTrafficPolicy != nil && *service.Spec.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyLocal && snapshot.AvailableOrUntracked("pods") {
			endpointNodes := map[string]struct{}{}
			for _, pod := range pods {
				if pod.Spec.NodeName != "" && podReady(pod) {
					endpointNodes[pod.Spec.NodeName] = struct{}{}
				}
			}
			blockedClients := []string{}
			for podIndex := range snapshot.Pods {
				client := &snapshot.Pods[podIndex]
				if client.Namespace != service.Namespace || client.Spec.NodeName == "" || client.Status.Phase == corev1.PodSucceeded || client.Status.Phase == corev1.PodFailed {
					continue
				}
				if _, localEndpoint := endpointNodes[client.Spec.NodeName]; localEndpoint || !podReferencesService(client, service) {
					continue
				}
				blockedClients = append(blockedClients, client.Name+"@"+client.Spec.NodeName)
			}
			if len(endpointNodes) > 0 && len(blockedClients) > 0 {
				result = append(result, model.NewFinding(model.Candidate, "K8S.SERVICE.INTERNAL_TRAFFIC_LOCAL_GAP", "Service", resource, "NoLocalEndpointOnSomeNodes", "internal-traffic-policy/local",
					fmt.Sprintf("Service %s は internalTrafficPolicy: Local ですが、このServiceを参照するPod %s のNodeにはReadyなローカルEndpointがありません。check.shと同じPod内Service接続では到達できません", shortRef(service.Namespace, service.Name), strings.Join(blockedClients, ", ")), 92,
					model.Evidence{Kind: "service", Key: "endpointNodes", Value: strings.Join(sortedStringSet(endpointNodes), ", ")},
					model.Evidence{Kind: "pod", Key: "clientsWithoutLocalEndpoint", Value: strings.Join(blockedClients, ", ")}))
			}
		}
		if snapshot.AvailableOrUntracked("pods") && len(pods) == 0 {
			evidence := []model.Evidence{
				{Kind: "service", Key: "spec.selector", Value: "Serviceのselector: " + serviceSelectorText(service.Spec.Selector)},
			}
			message := fmt.Sprintf("Service %s のPod選択条件（selector）に一致するPodが見つかりません", shortRef(service.Namespace, service.Name))
			// "Nothing matches" leaves the operator to diff the selector against
			// every Pod by hand. Naming the Pods that matched all but one label,
			// and the label that differs, is the whole answer in one line.
			if misses := nearestSelectorMisses(service, podIndex[service.Namespace], 3); len(misses) > 0 {
				message += fmt.Sprintf("。一部だけ一致しているPodがあります: %s", summarizeStrings(misses, 3))
				evidence = append(evidence, model.Evidence{Kind: "pod", Key: "nearestMatch", Value: "一部一致のPod: " + summarizeStrings(misses, 3)})
			}
			result = append(result, model.NewFinding(
				model.Warning, "K8S.SERVICE.SELECTOR_NO_MATCH", "Service", resource, "SelectorNoMatch", "selector-no-match",
				message, 75, evidence...,
			))
		}
		if snapshot.AvailableOrUntracked("pods") {
			result = append(result, partialSelectorFindings(service, podIndex[service.Namespace], pods, owners, resource)...)
		}
		ready, fallback := serviceEndpointCounts(service, snapshot)
		endpointDataAvailable := snapshot.AvailableOrUntracked("endpoint_slices") || snapshot.AvailableOrUntracked("endpoints")
		if snapshot.AvailableOrUntracked("pods") && endpointDataAvailable && len(pods) > 0 && ready == 0 && fallback == 0 {
			result = append(result, model.NewFinding(
				model.Warning, "K8S.SERVICE.NO_READY_ENDPOINT", "Service", resource, "NoReadyEndpoint", "ready-endpoint-zero",
				fmt.Sprintf("Service %s には、Ready状態のEndpointがありません", shortRef(service.Namespace, service.Name)), 85,
				model.Evidence{Kind: "service", Key: "selectorMatches", Value: selectedPodSummary(pods)},
				model.Evidence{Kind: "endpoint", Key: "ready", Value: "Ready状態のEndpoint: 0件"},
			))
		} else if snapshot.AvailableOrUntracked("pods") && endpointDataAvailable && len(pods) > 0 && ready == 0 && fallback > 0 {
			result = append(result, model.NewFinding(
				model.Warning, "K8S.SERVICE.TERMINATING_ENDPOINTS_ONLY", "Service", resource, "TerminatingEndpointsOnly", "terminating-serving-endpoints",
				fmt.Sprintf("Service %s にはReady状態のEndpointがなく、終了処理中で serving=true のEndpoint %d件だけが代替候補です", shortRef(service.Namespace, service.Name), fallback), 88,
				model.Evidence{Kind: "endpoint", Key: "terminatingServing", Value: fmt.Sprintf("終了処理中かつ serving=true のEndpoint: %d件", fallback)},
			))
		}
		for _, port := range service.Spec.Ports {
			if !snapshot.AvailableOrUntracked("pods") {
				break
			}
			target := serviceTargetPort(port)
			if target.Type != intstrutil.String || target.StrVal == "" {
				// A numeric targetPort need not be declared as a containerPort,
				// so it is judged separately and only ever as a Candidate.
				if finding, ok := numericTargetPortUndeclared(service, port, target, pods, resource, snapshot); ok {
					result = append(result, finding)
				}
				continue
			}
			protocol := string(port.Protocol)
			if protocol == "" {
				protocol = string(corev1.ProtocolTCP)
			}
			resolved := false
			namedPorts := map[string]struct{}{}
			for _, pod := range pods {
				_, named := containerPorts(pod)
				for name := range named[protocol] {
					namedPorts[name] = struct{}{}
				}
				if _, ok := named[protocol][target.StrVal]; ok {
					resolved = true
					break
				}
			}
			if !resolved && snapshot.AvailableOrUntracked("endpoint_slices") {
				resolved = endpointSliceResolvesPort(service, port, snapshot)
			}
			if !resolved && len(pods) > 0 {
				availableNames := sortedStringSet(namedPorts)
				portNamesEvidence := fmt.Sprintf("selectorに一致したPodに定義された %s の containerPort 名: なし", protocol)
				if len(availableNames) > 0 {
					portNamesEvidence = fmt.Sprintf("selectorに一致したPodに定義された %s の containerPort 名: %s", protocol, summarizeStrings(availableNames, 10))
				}
				evidence := []model.Evidence{
					{Kind: "service", Key: "spec.ports", Value: fmt.Sprintf("Serviceポート %s → targetPort %q", servicePortText(port), target.StrVal)},
					{Kind: "service", Key: "spec.selector", Value: "Serviceのselector: " + serviceSelectorText(service.Spec.Selector)},
					{Kind: "pod", Key: "selectorMatches", Value: selectedPodSummary(pods)},
					{Kind: "pod", Key: "containerPortNames", Value: portNamesEvidence},
					{Kind: "decision", Key: "unresolved", Value: fmt.Sprintf("selectorに一致したPodを確認しましたが、targetPort %q と同名の %s containerPort は見つかりませんでした（0件）", target.StrVal, protocol)},
				}
				if snapshot.AvailableOrUntracked("endpoint_slices") {
					evidence = append(evidence, model.Evidence{Kind: "endpointSlice", Key: "resolvedPort", Value: "EndpointSliceからも転送先ポートを確認できませんでした"})
				}
				result = append(result, model.NewFinding(
					model.Issue, "K8S.SERVICE.TARGET_PORT_UNRESOLVED", "Service", resource, "TargetPortUnresolved", port.Name+"/"+target.StrVal,
					fmt.Sprintf("Service %s のポート %s では、targetPort に %q が指定されています。しかし、selectorに一致したPodには、%q という名前の %s containerPort が定義されていないため、転送先ポートを解決できません", shortRef(service.Namespace, service.Name), servicePortText(port), target.StrVal, target.StrVal, protocol), 98,
					evidence...,
				))
			}
		}
		if service.Spec.Type == corev1.ServiceTypeLoadBalancer && len(service.Status.LoadBalancer.Ingress) == 0 && elapsedSince(snapshot, service.CreationTimestamp.Time) >= 5*time.Minute {
			result = append(result, model.NewFinding(model.Candidate, "K8S.SERVICE.LOAD_BALANCER_PENDING", "Service", resource, "LoadBalancerPending", "load-balancer", fmt.Sprintf("LoadBalancer Service %s には、外部アドレスがまだ割り当てられていません", shortRef(service.Namespace, service.Name)), 50))
		}
	}
	return result
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func externalNameTargetFinding(service *corev1.Service, snapshot *kube.Snapshot) (model.Finding, bool) {
	target := strings.TrimSuffix(strings.ToLower(service.Spec.ExternalName), ".")
	parts := strings.Split(target, ".")
	if len(parts) != 5 || parts[2] != "svc" || parts[3] != "cluster" || parts[4] != "local" {
		return model.Finding{}, false
	}
	name, namespace := parts[0], parts[1]
	// A namespace-scoped snapshot cannot prove that a Service outside the
	// collected namespace is absent. A cluster-wide snapshot can.
	if snapshot.ScopeNamespace != "" && namespace != snapshot.ScopeNamespace {
		return model.Finding{}, false
	}
	for i := range snapshot.Services {
		if snapshot.Services[i].Name == name && snapshot.Services[i].Namespace == namespace {
			return model.Finding{}, false
		}
	}
	return model.NewFinding(model.Warning, "K8S.SERVICE.EXTERNAL_NAME_TARGET_NOT_FOUND", "Service", ref("Service", service.Namespace, service.Name), "ExternalNameTargetNotFound", target,
		fmt.Sprintf("ExternalName Service %s の参照先 %q はクラスタ内Service名の形式ですが、Service %s/%s は存在しません。名前の誤りまたは削除済みの参照先が疑われます", shortRef(service.Namespace, service.Name), service.Spec.ExternalName, namespace, name), 90), true
}

func podReferencesService(pod *corev1.Pod, service *corev1.Service) bool {
	hosts := []string{
		service.Name,
		service.Name + "." + service.Namespace,
		service.Name + "." + service.Namespace + ".svc",
		service.Name + "." + service.Namespace + ".svc.cluster.local",
	}
	for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		for _, env := range container.Env {
			host := strings.TrimSuffix(strings.ToLower(environmentHost(strings.TrimSpace(env.Value))), ".")
			for _, candidate := range hosts {
				if host == candidate {
					return true
				}
			}
		}
		commandText := strings.ToLower(strings.Join(append(append([]string{}, container.Command...), container.Args...), " "))
		for _, candidate := range hosts {
			for _, prefix := range []string{"http://", "https://"} {
				if strings.Contains(commandText, prefix+candidate+"/") || strings.Contains(commandText, prefix+candidate+":") || strings.Contains(commandText, prefix+candidate+" ") {
					return true
				}
			}
		}
	}
	return false
}

// declaredPodPorts collects the ports a Pod's manifest positively states it
// uses: containerPorts of the given protocol, plus the numeric ports its probes
// connect to. A probe port counts on its own because kubelet is already
// reaching it, which proves a listener exists even when ports[] omits it.
func declaredPodPorts(pod *corev1.Pod, protocol string) map[int32]struct{} {
	ports := map[int32]struct{}{}
	numeric, _ := containerPorts(pod)
	for port := range numeric[protocol] {
		ports[port] = struct{}{}
	}
	if protocol != string(corev1.ProtocolTCP) {
		return ports
	}
	forEachPodProbe(pod, func(_ corev1.Container, _ string, probe *corev1.Probe) {
		var value intstrutil.IntOrString
		switch {
		case probe.HTTPGet != nil:
			value = probe.HTTPGet.Port
		case probe.TCPSocket != nil:
			value = probe.TCPSocket.Port
		default:
			return
		}
		if value.Type == intstrutil.Int && value.IntVal > 0 {
			ports[value.IntVal] = struct{}{}
		}
	})
	return ports
}

// numericTargetPortUndeclared reports a numeric targetPort that matches neither
// a declared containerPort nor a probe port on any selected Pod.
//
// Kubernetes does not require a numeric targetPort to appear in ports[], so a
// mismatch is not proof of a defect and this stays a Candidate. It is still
// worth raising, because this is the one Service misconfiguration where every
// other signal looks healthy: the selector matches, the Pod passes its probes
// and is Ready, and the EndpointSlice is populated — with the wrong port, since
// Kubernetes copies targetPort into the endpoint without checking that anything
// listens there. Nothing else in the diagnosis mentions the port at all, which
// is why "Pod is Running and Ready, endpoints exist, the Service still does not
// answer" is so hard to see.
//
// Requiring the selected Pods to declare at least one port of the same protocol
// keeps manifests that document nothing out of the finding: with no declared
// port anywhere there is no evidence either way, and guessing would be noise.
func numericTargetPortUndeclared(service *corev1.Service, port corev1.ServicePort, target intstrutil.IntOrString, pods []*corev1.Pod, resource string, snapshot *kube.Snapshot) (model.Finding, bool) {
	if target.Type != intstrutil.Int || target.IntVal <= 0 || len(pods) == 0 {
		return model.Finding{}, false
	}
	protocol := string(port.Protocol)
	if protocol == "" {
		protocol = string(corev1.ProtocolTCP)
	}
	declared := map[int32]struct{}{}
	for _, pod := range pods {
		podPorts := declaredPodPorts(pod, protocol)
		if _, matched := podPorts[target.IntVal]; matched {
			return model.Finding{}, false
		}
		for value := range podPorts {
			declared[value] = struct{}{}
		}
	}
	if len(declared) == 0 {
		return model.Finding{}, false
	}
	evidence := []model.Evidence{
		{Kind: "service", Key: "spec.ports", Value: fmt.Sprintf("Serviceポート %s → targetPort %d", servicePortText(port), target.IntVal)},
		{Kind: "service", Key: "spec.selector", Value: "Serviceのselector: " + serviceSelectorText(service.Spec.Selector)},
		{Kind: "pod", Key: "selectorMatches", Value: selectedPodSummary(pods)},
		{Kind: "pod", Key: "declaredPorts", Value: fmt.Sprintf("selectorに一致したPodが宣言している %s ポート（containerPortとProbeの合計）: %s", protocol, summarizeStrings(sortedInt32Set(declared), 10))},
		{Kind: "decision", Key: "undeclared", Value: fmt.Sprintf("targetPort %d は、いずれのPodの containerPort にもProbeのポートにも含まれていませんでした（0件）", target.IntVal)},
	}
	if snapshot.AvailableOrUntracked("endpoint_slices") {
		evidence = append(evidence, model.Evidence{Kind: "endpointSlice", Key: "resolvedPort", Value: "EndpointSliceにはtargetPortがそのまま記録されるため、待ち受けの有無はEndpointSliceからは確認できません"})
	}
	return model.NewFinding(
		model.Candidate, "K8S.SERVICE.TARGET_PORT_UNDECLARED", "Service", resource, "TargetPortUndeclared",
		port.Name+"/"+strconv.Itoa(int(target.IntVal)),
		fmt.Sprintf("Service %s のポート %s では、targetPort に %d が指定されています。しかし、selectorに一致したPodには、%d を使う containerPort もProbeも見つかりません。転送先で待ち受けているコンテナがない可能性があります。数値のtargetPortは宣言が不要なため、ports[] に書かずに待ち受けている場合は設定どおりです", shortRef(service.Namespace, service.Name), servicePortText(port), target.IntVal, target.IntVal), 55,
		evidence...,
	), true
}

func sortedInt32Set(values map[int32]struct{}) []string {
	result := make([]int, 0, len(values))
	for value := range values {
		result = append(result, int(value))
	}
	sort.Ints(result)
	text := make([]string, 0, len(result))
	for _, value := range result {
		text = append(text, strconv.Itoa(value))
	}
	return text
}

func servicePortText(port corev1.ServicePort) string {
	protocol := port.Protocol
	if protocol == "" {
		protocol = corev1.ProtocolTCP
	}
	value := fmt.Sprintf("%d/%s", port.Port, protocol)
	if port.Name != "" {
		return fmt.Sprintf("%q（%s）", port.Name, value)
	}
	return value
}

func serviceSelectorText(selector map[string]string) string {
	keys := make([]string, 0, len(selector))
	for key := range selector {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+selector[key])
	}
	return strings.Join(values, ", ")
}

func selectedPodSummary(pods []*corev1.Pod) string {
	refs := make([]string, 0, len(pods))
	for _, pod := range pods {
		refs = append(refs, shortRef(pod.Namespace, pod.Name))
	}
	sort.Strings(refs)
	return fmt.Sprintf("selectorに一致したPod: %d件（%s）", len(refs), summarizeStrings(refs, 5))
}

func sortedStringSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func summarizeStrings(values []string, limit int) string {
	if len(values) == 0 {
		return "なし"
	}
	if limit <= 0 || len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return fmt.Sprintf("%s, …（ほか%d件）", strings.Join(values[:limit], ", "), len(values)-limit)
}

func endpointSliceResolvesPort(service *corev1.Service, servicePort corev1.ServicePort, snapshot *kube.Snapshot) bool {
	protocol := servicePort.Protocol
	if protocol == "" {
		protocol = corev1.ProtocolTCP
	}
	for i := range snapshot.EndpointSlices {
		slice := &snapshot.EndpointSlices[i]
		if slice.Namespace != service.Namespace || slice.Labels["kubernetes.io/service-name"] != service.Name {
			continue
		}
		for _, endpointPort := range slice.Ports {
			endpointProtocol := corev1.ProtocolTCP
			if endpointPort.Protocol != nil {
				endpointProtocol = *endpointPort.Protocol
			}
			if endpointPort.Port == nil || endpointProtocol != protocol {
				continue
			}
			if servicePort.Name != "" {
				if endpointPort.Name != nil && *endpointPort.Name == servicePort.Name {
					return true
				}
				continue
			}
			if len(service.Spec.Ports) == 1 && (endpointPort.Name == nil || *endpointPort.Name == "") {
				return true
			}
		}
	}
	return false
}

func serviceEndpointCounts(service *corev1.Service, snapshot *kube.Snapshot) (ready, fallback int) {
	if endpointSlicesAuthoritative(snapshot) {
		for i := range snapshot.EndpointSlices {
			slice := &snapshot.EndpointSlices[i]
			if slice.Namespace != service.Namespace || slice.Labels["kubernetes.io/service-name"] != service.Name {
				continue
			}
			for _, endpoint := range slice.Endpoints {
				// EndpointSlice condition defaults are part of the API contract:
				// ready=nil and serving=nil mean true, terminating=nil means false.
				isReady := endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready
				isServing := endpoint.Conditions.Serving == nil || *endpoint.Conditions.Serving
				isTerminating := endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating
				switch {
				case isReady:
					ready++
				case isServing && isTerminating:
					fallback++
				}
			}
		}
		return ready, fallback
	}
	if snapshot.AvailableOrUntracked("endpoints") {
		for i := range snapshot.Endpoints {
			endpoint := &snapshot.Endpoints[i]
			if endpoint.Namespace != service.Namespace || endpoint.Name != service.Name {
				continue
			}
			for _, subset := range endpoint.Subsets {
				ready += len(subset.Addresses)
			}
		}
	}
	return ready, fallback
}

// A successful EndpointSlice list is authoritative even when it returns zero
// items. Legacy Endpoints is used only when EndpointSlice acquisition itself
// was unavailable, or by hand-built snapshots that contain no EndpointSlices.
func endpointSlicesAuthoritative(snapshot *kube.Snapshot) bool {
	status, tracked := snapshot.Statuses["endpoint_slices"]
	if tracked {
		return status.Available
	}
	return len(snapshot.EndpointSlices) > 0
}

// selectorMismatch explains why one Pod is not selected, naming the labels that
// do not line up. "No Pod matches" is true but useless on its own: the operator
// still has to diff a selector against every Pod by hand to find the one key
// that is spelled differently.
func selectorMismatch(selector map[string]string, pod *corev1.Pod) (matched int, reasons []string) {
	keys := make([]string, 0, len(selector))
	for key := range selector {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		want := selector[key]
		got, present := pod.Labels[key]
		switch {
		case present && got == want:
			matched++
		case present:
			reasons = append(reasons, fmt.Sprintf("%s: Service=%q / Pod=%q", key, want, got))
		default:
			reasons = append(reasons, fmt.Sprintf("%s: Service=%q / Podにラベルなし", key, want))
		}
	}
	return matched, reasons
}

// nearestSelectorMisses ranks the Pods that came closest to matching, so a
// selector that matches nothing can still point at the label to fix.
func nearestSelectorMisses(service *corev1.Service, candidates []*corev1.Pod, limit int) []string {
	type miss struct {
		matched int
		text    string
	}
	misses := []miss{}
	for _, pod := range candidates {
		matched, reasons := selectorMismatch(service.Spec.Selector, pod)
		if matched == 0 || len(reasons) == 0 {
			continue
		}
		misses = append(misses, miss{matched, fmt.Sprintf("%s（%d項目一致、不一致: %s）", pod.Name, matched, strings.Join(reasons, "、"))})
	}
	sort.SliceStable(misses, func(i, j int) bool { return misses[i].matched > misses[j].matched })
	result := []string{}
	for _, value := range misses {
		if len(result) >= limit {
			break
		}
		result = append(result, value.text)
	}
	return result
}

// workloadOwners resolves which top-level controller each Pod belongs to. The
// grouping decides what counts as "the same workload", so it has to survive the
// two ways the obvious answer is unavailable: ReplicaSets that were not
// collected, and Pods created without a controller at all.
type workloadOwners struct {
	replicaSets map[string]*appsv1.ReplicaSet
	controllers []workloadSelector
}

func newWorkloadOwners(snapshot *kube.Snapshot) workloadOwners {
	owners := workloadOwners{replicaSets: map[string]*appsv1.ReplicaSet{}}
	for i := range snapshot.ReplicaSets {
		owners.replicaSets[snapshot.ReplicaSets[i].Namespace+"/"+snapshot.ReplicaSets[i].Name] = &snapshot.ReplicaSets[i]
	}
	add := func(kind, namespace, name string, spec *metav1.LabelSelector) {
		selector, err := metav1.LabelSelectorAsSelector(spec)
		if err != nil || spec == nil || selector.Empty() {
			return
		}
		owners.controllers = append(owners.controllers, workloadSelector{kind, namespace, name, selector})
	}
	for i := range snapshot.Deployments {
		add("Deployment", snapshot.Deployments[i].Namespace, snapshot.Deployments[i].Name, snapshot.Deployments[i].Spec.Selector)
	}
	for i := range snapshot.StatefulSets {
		add("StatefulSet", snapshot.StatefulSets[i].Namespace, snapshot.StatefulSets[i].Name, snapshot.StatefulSets[i].Spec.Selector)
	}
	for i := range snapshot.DaemonSets {
		add("DaemonSet", snapshot.DaemonSets[i].Namespace, snapshot.DaemonSets[i].Name, snapshot.DaemonSets[i].Spec.Selector)
	}
	return owners
}

// of names the workload a Pod belongs to, in order of how much the answer can
// be trusted.
func (owners workloadOwners) of(pod *corev1.Pod) string {
	for _, owner := range pod.OwnerReferences {
		if owner.Controller == nil || !*owner.Controller {
			continue
		}
		if owner.Kind != "ReplicaSet" {
			return owner.Kind + "/" + owner.Name
		}
		if replicaSet, ok := owners.replicaSets[pod.Namespace+"/"+owner.Name]; ok {
			for _, parent := range replicaSet.OwnerReferences {
				if parent.Controller != nil && *parent.Controller {
					return parent.Kind + "/" + parent.Name
				}
			}
		}
		// The ReplicaSet was not collected. Naming it directly would split one
		// rollout into two groups and hide exactly the mismatch this looks for,
		// so fall through to the controller whose selector claims this Pod.
		break
	}
	for _, controller := range owners.controllers {
		if controller.namespace == pod.Namespace && controller.selector.Matches(labels.Set(pod.Labels)) {
			return controller.kind + "/" + controller.name
		}
	}
	return ""
}

// matchedSelectorPairs lists the selector entries a Pod satisfies exactly. Two
// Pods sharing one of these are related to this Service even when nothing in the
// cluster records a controller for either of them; two Pods sharing none are
// simply different applications that happen to use the same label key.
func matchedSelectorPairs(selector map[string]string, pod *corev1.Pod) map[string]struct{} {
	pairs := map[string]struct{}{}
	for key, want := range selector {
		if got, ok := pod.Labels[key]; ok && got == want {
			pairs[key+"="+want] = struct{}{}
		}
	}
	return pairs
}

// relatedToSelectedPod reports whether an unselected Pod belongs with the Pods
// this Service does reach. Grouping owner-less Pods by label keys alone pulled
// in unrelated applications: app=web and app=api share the key and nothing else.
func relatedToSelectedPod(selector map[string]string, pod *corev1.Pod, selected []*corev1.Pod) bool {
	pairs := matchedSelectorPairs(selector, pod)
	if len(pairs) == 0 {
		return false
	}
	for _, other := range selected {
		for pair := range matchedSelectorPairs(selector, other) {
			if _, shared := pairs[pair]; shared {
				return true
			}
		}
	}
	return false
}

// partialSelectorFindings reports a Service that reaches only part of a
// workload.
//
// Nothing marks this state: the Service has Endpoints, every Pod is Ready, and
// no counter anywhere says that some replicas receive no traffic. It happens
// when the selector uses a label that is not stable across revisions, so one
// ReplicaSet's Pods match and the other's do not — capacity silently shrinks,
// and the Service goes dark entirely once the matching side scales to zero.
func partialSelectorFindings(service *corev1.Service, candidates []*corev1.Pod, selected []*corev1.Pod, owners workloadOwners, resource string) []model.Finding {
	if len(selected) == 0 || len(candidates) == len(selected) {
		return nil
	}
	isSelected := map[string]bool{}
	for _, pod := range selected {
		isSelected[pod.Name] = true
	}
	type group struct{ selected, missed []*corev1.Pod }
	groups := map[string]*group{}
	order := []string{}
	const unowned = "コントローラを持たないPod"
	for _, pod := range candidates {
		owner := owners.of(pod)
		if owner == "" {
			// Nothing in the cluster says what this Pod belongs to, so relate it
			// to the Pods the Service already reaches instead of guessing.
			if isSelected[pod.Name] || !relatedToSelectedPod(service.Spec.Selector, pod, selected) {
				continue
			}
			owner = unowned
		}
		if _, seen := groups[owner]; !seen {
			groups[owner] = &group{}
			order = append(order, owner)
		}
		if isSelected[pod.Name] {
			groups[owner].selected = append(groups[owner].selected, pod)
		} else {
			groups[owner].missed = append(groups[owner].missed, pod)
		}
	}
	result := []model.Finding{}
	for _, owner := range order {
		value := groups[owner]
		// Only a workload that is split by this selector is evidence of a
		// mismatch. One that is entirely outside the Service is simply a
		// different application. The owner-less group is built from Pods already
		// shown to be related to a selected one, so it needs no selected member
		// of its own.
		if len(value.missed) == 0 || (owner != unowned && len(value.selected) == 0) {
			continue
		}
		details := []string{}
		for _, pod := range value.missed {
			_, reasons := selectorMismatch(service.Spec.Selector, pod)
			details = append(details, fmt.Sprintf("%s（%s）", pod.Name, strings.Join(reasons, "、")))
		}
		total := len(value.selected) + len(value.missed)
		if owner == unowned {
			total = len(selected) + len(value.missed)
			value.selected = selected
		}
		result = append(result, model.NewFinding(
			model.Warning, "K8S.SERVICE.SELECTOR_PARTIAL_MATCH", "Service", resource, "SelectorPartialMatch", "partial/"+owner,
			fmt.Sprintf("Service %s のPod選択条件（selector）は、%s のPod %d個のうち %d個にしか一致していません。残りのPodには通信が振り分けられず、一致している側が0台になるとこのServiceは応答しなくなります。対象外のPod: %s",
				shortRef(service.Namespace, service.Name), owner, total, len(value.selected), summarizeStrings(details, 3)), 70,
			model.Evidence{Kind: "service", Key: "spec.selector", Value: "Serviceのselector: " + serviceSelectorText(service.Spec.Selector)},
			model.Evidence{Kind: "pod", Key: "selected", Value: fmt.Sprintf("%s のうち一致 %d個 / 不一致 %d個", owner, len(value.selected), len(value.missed))},
			model.Evidence{Kind: "decision", Key: "mismatch", Value: "不一致の内訳: " + summarizeStrings(details, 5)},
		))
	}
	return result
}
