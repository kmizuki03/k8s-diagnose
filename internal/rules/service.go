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
	corev1 "k8s.io/api/core/v1"
	intstrutil "k8s.io/apimachinery/pkg/util/intstr"
)

type ServiceRule struct{}

func (ServiceRule) Metadata() Metadata {
	permissions := namespaced("", "services,pods,endpoints")
	permissions = append(permissions, namespaced("discovery.k8s.io", "endpointslices")...)
	return Metadata{
		ID: "services", Section: "Service", Description: "ServiceのPod選択条件・Endpoint・targetPort",
		Required:    []string{"services"},
		Optional:    []string{"pods", "endpoint_slices", "endpoints"},
		Permissions: permissions, Modes: []string{"all", "triage", "select"},
	}
}

func (ServiceRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	podIndex := indexPodsByNamespace(snapshot.Pods)
	for i := range snapshot.Services {
		service := &snapshot.Services[i]
		if service.Spec.Type == corev1.ServiceTypeExternalName || len(service.Spec.Selector) == 0 {
			continue
		}
		resource := ref("Service", service.Namespace, service.Name)
		pods := podIndex.selected(service)
		if snapshot.AvailableOrUntracked("pods") && len(pods) == 0 {
			result = append(result, model.NewFinding(
				model.Warning, "K8S.SERVICE.SELECTOR_NO_MATCH", "Service", resource, "SelectorNoMatch", "selector-no-match",
				fmt.Sprintf("Service %s のPod選択条件（selector）に一致するPodが見つかりません", shortRef(service.Namespace, service.Name)), 75,
				model.Evidence{Kind: "service", Key: "spec.selector", Value: "Serviceのselector: " + serviceSelectorText(service.Spec.Selector)},
			))
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
