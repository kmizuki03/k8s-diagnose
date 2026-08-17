// Package connect reproduces Pod HTTP/TCP probes through client-go port-forwarding.
package connect

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	"github.com/kmizuki03/k8s-diagnose/internal/redact"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/portforward"
	transportspdy "k8s.io/client-go/transport/spdy"
)

type Target struct {
	Container  string
	ProbeType  string
	Group      string
	Label      string
	Protocol   string
	RemotePort int
	PortName   string
	Path       string
	// RawPath and RawQuery are used only by a manually pasted URL. Kubernetes
	// HTTPGetAction.path is deliberately stored in Path alone so '?' and '#'
	// remain literal escaped path characters, matching kubelet.
	RawPath     string
	RawQuery    string
	Scheme      string
	Headers     []corev1.HTTPHeader
	Probe       *corev1.Probe
	Source      string
	Strict      bool
	Active      bool
	Unavailable bool
	Invalid     bool
	Inactive    string
	// ServiceName and ServicePort identify the Service a "service" group target
	// was derived from. The check itself always tunnels to the Pod under
	// diagnosis, but kubectl also accepts service/NAME, and that form is worth
	// printing: it makes kubectl resolve the selector, the endpoints and the
	// service port → targetPort mapping, which is the part a Pod-pinned tunnel
	// skips over.
	ServiceName string
	ServicePort int32
}

type Result struct {
	Target      Target
	LocalPort   int
	Successful  bool
	Tested      bool
	Warned      bool
	StatusCode  int
	ContentType string
	BodyBytes   int
	Detail      string
	Body        string
	// Proto and Header carry the response line and headers for display only, the
	// same way Body does. Findings keep only the status code, Content-Type and
	// byte count, so nothing here reaches a report, a snapshot, the history
	// database or a webhook.
	Proto  string
	Header http.Header
	// Shared marks a result copied from an earlier target that resolved to the
	// same destination and would have issued a byte-for-byte identical request.
	// The row is still reported so both groups stay visible, but no second
	// tunnel is opened, no second request is sent, and no duplicate finding is
	// raised for what is one and the same fact.
	Shared bool
}

func Targets(pod *corev1.Pod, services []corev1.Service, pathOverride string) []Target {
	return targetsAt(pod, services, pathOverride, time.Now())
}

func targetsAt(pod *corev1.Pod, services []corev1.Service, pathOverride string, now time.Time) []Target {
	result := []Target{}
	addContainer := func(container corev1.Container) {
		probes := []struct {
			name  string
			probe *corev1.Probe
		}{{"readinessProbe", container.ReadinessProbe}, {"livenessProbe", container.LivenessProbe}, {"startupProbe", container.StartupProbe}}
		for _, value := range probes {
			if value.probe == nil {
				continue
			}
			if get := value.probe.HTTPGet; get != nil {
				port, ok := resolvePort(get.Port, container)
				if !ok {
					result = append(result, Target{
						Container: container.Name, ProbeType: value.name, Group: "pod", Label: value.name,
						Protocol: "http", PortName: get.Port.StrVal, Path: get.Path, Scheme: strings.ToLower(string(get.Scheme)),
						Headers: append([]corev1.HTTPHeader{}, get.HTTPHeaders...), Probe: value.probe, Source: "probe",
						Strict: true, Invalid: true, Inactive: fmt.Sprintf("コンテナ %q の ports[].name には、ポート名 %q が定義されていません", container.Name, get.Port.StrVal),
					})
					continue
				}
				path := get.Path
				if path == "" {
					path = "/"
				}
				strict := pathOverride == "" || pathOverride == path
				if pathOverride != "" {
					path = pathOverride
				}
				scheme := strings.ToLower(string(get.Scheme))
				if scheme == "" {
					scheme = "http"
				}
				active, inactive := probeActive(pod, container.Name, value.name, value.probe, now)
				unavailable := false
				if active && get.Host != "" {
					active = false
					unavailable = true
					inactive = fmt.Sprintf("httpGet.host で指定された接続先 %q は、port-forwardでは再現できません", get.Host)
				}
				result = append(result, Target{
					Container: container.Name, ProbeType: value.name, Group: "pod",
					Label: value.name, Protocol: "http", RemotePort: port,
					PortName: get.Port.StrVal, Path: path, Scheme: scheme,
					Headers: append([]corev1.HTTPHeader{}, get.HTTPHeaders...), Probe: value.probe,
					Source: "probe", Strict: strict, Active: active, Unavailable: unavailable, Inactive: inactive,
				})
			}
			if tcp := value.probe.TCPSocket; tcp != nil {
				port, ok := resolvePort(tcp.Port, container)
				if !ok {
					result = append(result, Target{Container: container.Name, ProbeType: value.name, Group: "pod", Label: value.name, Protocol: "tcp", PortName: tcp.Port.StrVal, Probe: value.probe, Source: "probe", Strict: true, Invalid: true, Inactive: fmt.Sprintf("コンテナ %q の ports[].name には、ポート名 %q が定義されていません", container.Name, tcp.Port.StrVal)})
				} else {
					active, inactive := probeActive(pod, container.Name, value.name, value.probe, now)
					unavailable := false
					if active && tcp.Host != "" {
						active = false
						unavailable = true
						inactive = fmt.Sprintf("tcpSocket.host で指定された接続先 %q は、port-forwardでは再現できません", tcp.Host)
					}
					result = append(result, Target{Container: container.Name, ProbeType: value.name, Group: "pod", Label: value.name, Protocol: "tcp", RemotePort: port, PortName: tcp.Port.StrVal, Probe: value.probe, Source: "probe", Strict: true, Active: active, Unavailable: unavailable, Inactive: inactive})
				}
			}
		}
	}
	for _, container := range pod.Spec.InitContainers {
		if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			addContainer(container)
		}
	}
	for _, container := range pod.Spec.Containers {
		addContainer(container)
	}
	probePorts := map[int]bool{}
	for _, target := range result {
		if target.RemotePort > 0 {
			probePorts[target.RemotePort] = true
		}
	}
	for _, container := range servicePortContainers(pod) {
		for _, port := range container.Ports {
			if port.Protocol != "" && port.Protocol != corev1.ProtocolTCP || probePorts[int(port.ContainerPort)] {
				continue
			}
			result = append(result, Target{Container: container.Name, Group: "pod", Label: container.Name, Protocol: "tcp", RemotePort: int(port.ContainerPort), PortName: port.Name, Source: "containerPort", Active: true})
			probePorts[int(port.ContainerPort)] = true
		}
	}
	matchingServices := []corev1.Service{}
	for i := range services {
		service := services[i]
		if service.Namespace == pod.Namespace && selectorMatches(service.Spec.Selector, pod.Labels) {
			matchingServices = append(matchingServices, service)
		}
	}
	// If the manifest has neither probes nor containerPorts, a numeric Service
	// targetPort is still enough to perform a plain TCP check against the Pod.
	if len(result) == 0 {
		for i := range matchingServices {
			for _, servicePort := range matchingServices[i].Spec.Ports {
				if serviceProtocol(servicePort) != corev1.ProtocolTCP {
					continue
				}
				remote, _, ok := resolveServicePort(servicePort, pod)
				if !ok || probePorts[remote] {
					continue
				}
				result = append(result, Target{Container: "Service " + matchingServices[i].Name + "から推定", Group: "pod", Label: "Serviceから推定", Protocol: "tcp", RemotePort: remote, Source: "service-inference", Active: true})
				probePorts[remote] = true
			}
		}
	}
	podTargets := append([]Target{}, result...)
	for i := range matchingServices {
		service := &matchingServices[i]
		for _, servicePort := range service.Spec.Ports {
			if servicePort.Protocol != "" && servicePort.Protocol != corev1.ProtocolTCP {
				continue
			}
			remote, targetName, ok := resolveServicePort(servicePort, pod)
			if !ok {
				continue
			}
			targetText := targetName
			if targetText == "" {
				targetText = strconv.Itoa(remote)
			}
			target := Target{Group: "service", Label: fmt.Sprintf("svc/%s :%d→%s", service.Name, servicePort.Port, targetText), Protocol: "tcp", RemotePort: remote, PortName: targetName, Source: "service", Strict: false, Active: true, ServiceName: service.Name, ServicePort: servicePort.Port}
			for _, probeTarget := range podTargets {
				if probeTarget.Source != "probe" || probeTarget.Protocol != "http" || !probeTarget.Active {
					continue
				}
				if probeTarget.RemotePort == remote || targetName != "" && probeTarget.PortName == targetName {
					target.Container, target.ProbeType = probeTarget.Container, probeTarget.ProbeType
					target.Protocol, target.Path, target.RawPath, target.RawQuery, target.Scheme = "http", probeTarget.Path, probeTarget.RawPath, probeTarget.RawQuery, probeTarget.Scheme
					target.Headers, target.Probe, target.Strict = append([]corev1.HTTPHeader{}, probeTarget.Headers...), probeTarget.Probe, probeTarget.Strict
					break
				}
			}
			result = append(result, target)
		}
	}
	return result
}

func resolveServicePort(port corev1.ServicePort, pod *corev1.Pod) (int, string, bool) {
	target := port.TargetPort
	if target.Type == intstr.Int && target.IntVal == 0 {
		target = intstr.FromInt32(port.Port)
	}
	if target.Type == intstr.Int {
		value := int(target.IntVal)
		return value, "", value >= 1 && value <= 65535
	}
	protocol := serviceProtocol(port)
	for _, container := range servicePortContainers(pod) {
		for _, candidate := range container.Ports {
			candidateProtocol := candidate.Protocol
			if candidateProtocol == "" {
				candidateProtocol = corev1.ProtocolTCP
			}
			if candidate.Name == target.StrVal && candidateProtocol == protocol {
				value := int(candidate.ContainerPort)
				return value, target.StrVal, value >= 1 && value <= 65535
			}
		}
	}
	return 0, target.StrVal, false
}

// servicePortContainers mirrors the Kubernetes EndpointSlice controller's
// named targetPort lookup: regular containers first, followed only by
// restartable init containers (native sidecars). Ordinary init containers are
// not running while the Pod serves traffic and therefore cannot back a Service.
func servicePortContainers(pod *corev1.Pod) []corev1.Container {
	result := append([]corev1.Container{}, pod.Spec.Containers...)
	for _, container := range pod.Spec.InitContainers {
		if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			result = append(result, container)
		}
	}
	return result
}

func serviceProtocol(port corev1.ServicePort) corev1.Protocol {
	if port.Protocol == "" {
		return corev1.ProtocolTCP
	}
	return port.Protocol
}

func probeActive(pod *corev1.Pod, container, probeType string, probe *corev1.Probe, now time.Time) (bool, string) {
	var status *corev1.ContainerStatus
	for i := range pod.Status.InitContainerStatuses {
		if pod.Status.InitContainerStatuses[i].Name == container {
			status = &pod.Status.InitContainerStatuses[i]
			break
		}
	}
	if status == nil {
		for i := range pod.Status.ContainerStatuses {
			if pod.Status.ContainerStatuses[i].Name == container {
				status = &pod.Status.ContainerStatuses[i]
				break
			}
		}
	}
	if status == nil || status.State.Running == nil {
		return false, "コンテナがRunning状態ではありません"
	}
	if probeType == "startupProbe" && status.Started != nil && *status.Started {
		return false, "startupProbeはすでに成功しています"
	}
	if probeType != "startupProbe" {
		var hasStartup bool
		for _, value := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
			if value.Name == container && value.StartupProbe != nil {
				hasStartup = true
				break
			}
		}
		if hasStartup && (status.Started == nil || !*status.Started) {
			return false, "startupProbeの完了を待っています"
		}
	}
	if probe.InitialDelaySeconds > 0 && now.Sub(status.State.Running.StartedAt.Time) < time.Duration(probe.InitialDelaySeconds)*time.Second {
		return false, "initialDelaySecondsで指定された待機時間内です"
	}
	return true, ""
}

func resolvePort(port intstr.IntOrString, container corev1.Container) (int, bool) {
	if port.Type == intstr.Int {
		value := int(port.IntVal)
		return value, value >= 1 && value <= 65535
	}
	for _, candidate := range container.Ports {
		if candidate.Name == port.StrVal {
			return int(candidate.ContainerPort), true
		}
	}
	return 0, false
}

func namedContainerPortSummary(pod *corev1.Pod, containerName string) string {
	var names []string
	collect := func(container corev1.Container) bool {
		if container.Name != containerName {
			return false
		}
		for _, port := range container.Ports {
			if port.Name != "" {
				names = append(names, port.Name)
			}
		}
		return true
	}
	for _, container := range pod.Spec.Containers {
		if collect(container) {
			break
		}
	}
	if len(names) == 0 {
		for _, container := range pod.Spec.InitContainers {
			if collect(container) {
				break
			}
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("コンテナ %q の ports[].name に定義された名前: なし", containerName)
	}
	return fmt.Sprintf("コンテナ %q の ports[].name に定義された名前: %s", containerName, strings.Join(names, ", "))
}

func selectorMatches(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

type Checker struct {
	Clients *kube.Clients
	Config  config.Config
}

func (checker *Checker) Check(ctx context.Context, pod *corev1.Pod, services []corev1.Service) ([]Result, []model.Finding) {
	now := checker.Clients.ServerTime()
	if now.IsZero() {
		now = time.Now()
	}
	targets := targetsAt(pod, services, checker.Config.ConnectPath, now)
	results, findings := []Result{}, []model.Finding{}
	base := checker.Config.ConnectPort
	if base == 0 {
		base = randomBasePort(len(targets))
	}
	offset := 0
	// A Service whose targetPort resolves to a port the Pod group already covers
	// produces a second target aimed at the very same destination. That pairing
	// is the point of having two groups — when the ports differ, the difference
	// is the diagnosis — but when they coincide there is nothing left to compare,
	// and opening a second port-forward would only repeat the identical request.
	// port-forward is the most expensive and most failure-prone thing this tool
	// does, so the earlier result is reused instead.
	checkedPodTargets := map[string]int{}
	for _, target := range targets {
		if !target.Active {
			results = append(results, Result{Target: target, Detail: "未実施: " + target.Inactive})
			if target.Invalid {
				findings = append(findings, model.NewFinding(model.Issue, "K8S.PROBE.PORT_UNRESOLVED", "Probe", targetResource(target, pod), "NamedPortUnresolved", probePortStableKey(target), fmt.Sprintf("Pod %s/%s のコンテナ %q に設定された %s のポート %q を解決できません。同じコンテナの ports[].name には、%q が定義されていません", pod.Namespace, pod.Name, target.Container, targetName(target), target.PortName, target.PortName), 100,
					model.Evidence{Kind: "probe", Key: "portName", Value: fmt.Sprintf("%s.port: %q", targetName(target), target.PortName)},
					model.Evidence{Kind: "container", Key: "ports[].name", Value: namedContainerPortSummary(pod, target.Container)},
					model.Evidence{Kind: "decision", Key: "unresolved", Value: fmt.Sprintf("ポート名 %q に対応する containerPort は見つかりませんでした（0件）", target.PortName)},
				))
			} else if target.Unavailable {
				findings = append(findings, model.NewFinding(model.Unavailable, "K8S.CONNECT.PROBE_HOST_UNSUPPORTED", "Probe確認", targetResource(target, pod), "ProbeHostNotReproduced", target.Group+"/"+targetName(target)+"/host", fmt.Sprintf("%sを実施できません。理由: %s", connectionTargetDescription(target, pod), target.Inactive), 100,
					model.Evidence{Kind: "probe", Key: "host", Value: probeHost(target)},
				))
			}
			continue
		}
		if index, duplicate := reusablePodResult(target, checkedPodTargets); duplicate {
			results = append(results, sharedResult(results[index], target))
			continue
		}
		local := base + offset
		offset++
		if local > 65535 {
			results = append(results, Result{Target: target, LocalPort: local, Detail: "ローカルポート範囲外"})
			findings = append(findings, model.NewFinding(model.Unavailable, "K8S.CONNECT.LOCAL_PORT_UNAVAILABLE", "接続確認", "Pod/"+pod.Namespace+"/"+pod.Name, "LocalPortRange", target.Group+"/local-port-range", fmt.Sprintf("接続確認に使用するローカルポート %d が上限の65535を超えるため、この対象は確認できません", local), 100))
			continue
		}
		result, err := checker.checkOne(ctx, pod, target, local)
		results = append(results, result)
		if target.Group == "pod" {
			checkedPodTargets[checkSignature(target)] = len(results) - 1
		}
		if err != nil {
			results[len(results)-1].Tested = false
			findings = append(findings, model.NewFinding(model.Unavailable, "K8S.CONNECT.PORT_FORWARD_UNAVAILABLE", "接続確認", targetResource(target, pod), "PortForwardFailed", target.Group+"/"+targetName(target)+"/"+strconv.Itoa(target.RemotePort), fmt.Sprintf("%s へのport-forwardを開始できないため、接続確認を実施できません。原因: %v", connectionTargetDescription(target, pod), err), 100))
			continue
		}
		if !result.Successful {
			code, section, confidence := "K8S.CONNECT.TCP_FAILED", "接続確認", 65
			if target.Protocol == "http" {
				code = "K8S.CONNECT.HTTP_UNREACHABLE"
				if result.StatusCode > 0 {
					code = "K8S.CONNECT.HTTP_FAILED"
				}
			}
			if target.Source == "probe" && target.Group == "pod" {
				section, confidence = "Probe確認", 72
				if target.Protocol == "tcp" {
					code = "K8S.PROBE.TCP_FAILED"
				} else if result.StatusCode > 0 {
					code = "K8S.PROBE.HTTP_FAILED"
				} else {
					code = "K8S.PROBE.UNREACHABLE"
				}
			}
			findings = append(findings, model.NewFinding(model.Warning, code, section, targetResource(target, pod), targetName(target), target.Group+"/"+targetName(target)+"/"+strconv.Itoa(target.RemotePort), fmt.Sprintf("%s への単発の接続確認に失敗しました。結果: %s", connectionTargetDescription(target, pod), result.Detail), confidence,
				connectEvidence(result)...,
			))
			// Threshold/period evaluation is not reproduced by this one-shot
			// check, so retain those limitations as separate evidence.
			last := &findings[len(findings)-1]
			last.Evidence = append(last.Evidence,
				model.Evidence{Kind: "connect", Key: "sampleCount", Value: "1"},
				model.Evidence{Kind: "connect", Key: "kubeletThresholdEvaluation", Value: "not-reproduced"},
			)
		} else if result.Warned {
			findings = append(findings, model.NewFinding(model.Warning, "K8S.CONNECT.HTTP_RESPONSE_WARNING", "接続確認", targetResource(target, pod), "HTTPResponseWarning", target.Group+"/"+targetName(target)+"/"+strconv.Itoa(target.RemotePort), fmt.Sprintf("%s から応答はありましたが、注意が必要です。結果: %s", connectionTargetDescription(target, pod), result.Detail), 60, connectEvidence(result)...))
		}
	}
	return results, findings
}

func connectEvidence(result Result) []model.Evidence {
	evidence := []model.Evidence{{Kind: "connect", Key: "detail", Value: result.Detail}}
	if result.Target.Probe != nil {
		probe := result.Target.Probe
		evidence = append(evidence,
			model.Evidence{Kind: "probe", Key: "type", Value: result.Target.ProbeType},
			model.Evidence{Kind: "probe", Key: "protocol", Value: result.Target.Protocol},
			model.Evidence{Kind: "probe", Key: "port", Value: strconv.Itoa(result.Target.RemotePort)},
			model.Evidence{Kind: "probe", Key: "timeoutSeconds", Value: strconv.Itoa(int(probe.TimeoutSeconds))},
			model.Evidence{Kind: "probe", Key: "periodSeconds", Value: strconv.Itoa(int(probe.PeriodSeconds))},
			model.Evidence{Kind: "probe", Key: "failureThreshold", Value: strconv.Itoa(int(probe.FailureThreshold))},
		)
		if result.Target.Path != "" {
			evidence = append(evidence, model.Evidence{Kind: "probe", Key: "path", Value: result.Target.Path})
		}
		if result.Target.Scheme != "" {
			evidence = append(evidence, model.Evidence{Kind: "probe", Key: "scheme", Value: result.Target.Scheme})
		}
	}
	if result.StatusCode > 0 {
		evidence = append(evidence, model.Evidence{Kind: "http", Key: "statusCode", Value: strconv.Itoa(result.StatusCode)})
	}
	if result.ContentType != "" {
		evidence = append(evidence, model.Evidence{Kind: "http", Key: "contentType", Value: result.ContentType})
	}
	if result.StatusCode > 0 {
		evidence = append(evidence, model.Evidence{Kind: "http", Key: "bodyBytesRead", Value: strconv.Itoa(result.BodyBytes)})
	}
	return evidence
}

func probePortStableKey(target Target) string {
	return target.Container + "/" + target.ProbeType + "/port/" + target.PortName
}

// ManualTarget parses an operator-typed destination into a check.
//
// The automatic targets only cover ports the manifest already declares, which
// is not where an investigation usually ends up: the interesting port is often
// an admin or metrics endpoint nothing references, and the interesting path is
// whatever the application actually serves. One field is accepted rather than
// three because the shape people already have in mind is a URL.
//
//	9000                            port 9000 へのTCP接続だけを確認
//	8080/healthz                    http://…:8080/healthz を確認
//	https://8443/metrics            TLSで確認（証明書の検証は行わない）
//	http://localhost:8080/secure    curlに渡すURLをそのまま貼れる
//
// A bare port stays a TCP check on purpose: sending an HTTP request to a port
// that speaks something else proves nothing about whether it is healthy.
//
// A host is accepted only when it is the loopback address, because that is what
// the forwarded port genuinely is. Any other host is refused rather than
// ignored: silently checking the Pod after being handed another destination
// would answer a question nobody asked.
func ManualTarget(input string) (Target, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return Target{}, errors.New("確認先が空です")
	}
	scheme, authority := "", ""
	path, rawPath, rawQuery := "", "", ""
	hasHTTPPart := false
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" {
			return Target{}, fmt.Errorf("接続先URLとして解釈できません: %q", input)
		}
		if parsed.User != nil {
			return Target{}, errors.New("接続先URLにユーザー情報は指定できません")
		}
		if parsed.Fragment != "" {
			return Target{}, errors.New("URLフラグメント（#以降）はHTTP要求へ送信されないため指定できません")
		}
		scheme, authority = strings.ToLower(parsed.Scheme), parsed.Host
		path, rawPath, rawQuery = parsed.Path, parsed.RawPath, parsed.RawQuery
		hasHTTPPart = true
	} else {
		if strings.Contains(value, "#") {
			return Target{}, errors.New("URLフラグメント（#以降）はHTTP要求へ送信されないため指定できません")
		}
		index := strings.IndexAny(value, "/?")
		if index < 0 {
			authority = value
		} else {
			authority = value[:index]
			parsed, err := url.Parse("http://localhost" + value[index:])
			if err != nil {
				return Target{}, fmt.Errorf("接続先として解釈できません: %q", input)
			}
			path, rawPath, rawQuery = parsed.Path, parsed.RawPath, parsed.RawQuery
			hasHTTPPart = true
		}
	}
	portText := strings.TrimSpace(authority)
	if strings.Contains(portText, ":") {
		host, hostPort, splitErr := net.SplitHostPort(portText)
		if splitErr != nil {
			return Target{}, fmt.Errorf("接続先として解釈できません: %q", authority)
		}
		if !loopbackHost(host) {
			return Target{}, fmt.Errorf("ホスト %q は指定できません。確認は選択したPodへのport-forward経由で行うため、localhost / 127.0.0.1 かポート番号だけを指定してください", host)
		}
		portText = hostPort
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Target{}, fmt.Errorf("ポート番号として解釈できません: %q（1〜65535の数値で指定してください）", portText)
	}
	if !hasHTTPPart && scheme == "" {
		return Target{
			Group: "manual", Label: fmt.Sprintf("手動確認 :%d", port), Protocol: "tcp",
			RemotePort: port, Source: "manual", Active: true,
		}, nil
	}
	if scheme == "" {
		scheme = "http"
	}
	if path == "" {
		path = "/"
	}
	target := Target{
		Group: "manual", Protocol: "http", Scheme: scheme, Path: path, RawPath: rawPath, RawQuery: rawQuery,
		RemotePort: port, Source: "manual", Active: true,
		// Strict is false: an operator poking at an arbitrary endpoint is
		// exploring, not asserting that a non-2xx answer is a cluster defect.
		Strict: false,
	}
	target.Label = "手動確認 " + targetLocalURL(target, port)
	return target, nil
}

// loopbackHost reports whether a typed host names the local end of the tunnel.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

// CheckTarget runs a single check against an explicitly chosen destination,
// reusing the same tunnel, timeouts and judgement as the automatic checks.
func (checker *Checker) CheckTarget(ctx context.Context, pod *corev1.Pod, target Target, local int) (Result, error) {
	return checker.checkOne(ctx, pod, target, local)
}

// NextLocalPort picks a local port for an extra check that will not collide
// with the ones the automatic checks already bound.
func NextLocalPort(results []Result) int {
	highest := 0
	for _, result := range results {
		highest = max(highest, result.LocalPort)
	}
	if highest < 1 || highest >= 65535 {
		return randomBasePort(1)
	}
	return highest + 1
}

func randomBasePort(targets int) int {
	if targets < 1 {
		targets = 1
	}
	maximum := min(59999, 65535-targets+1)
	if maximum <= 10000 {
		return 10000
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum-10000+1)))
	if err != nil {
		return 18080
	}
	return 10000 + int(value.Int64())
}

func targetName(target Target) string {
	if target.ProbeType != "" {
		return target.ProbeType
	}
	if target.Label != "" {
		return target.Label
	}
	return "port"
}

func targetResource(target Target, pod *corev1.Pod) string {
	if target.Group == "service" {
		name := strings.TrimPrefix(strings.Fields(target.Label)[0], "svc/")
		return "Service/" + pod.Namespace + "/" + name
	}
	if target.ProbeType != "" {
		return fmt.Sprintf("Probe/%s/%s/%s/%s", pod.Namespace, pod.Name, target.Container, target.ProbeType)
	}
	return "Pod/" + pod.Namespace + "/" + pod.Name
}

// checkSignature identifies the request a target would issue. Two targets share
// a signature only when the tunnel destination and the whole request are equal,
// so reusing a result can never hide a difference that would have been tested:
// a Service pointing at a different port, path or scheme keeps its own check.
func checkSignature(target Target) string {
	headers := make([]string, 0, len(target.Headers))
	for _, header := range target.Headers {
		headers = append(headers, header.Name+": "+header.Value)
	}
	timeoutSeconds := int32(0)
	if target.Probe != nil {
		timeoutSeconds = target.Probe.TimeoutSeconds
	}
	return strings.Join([]string{
		strconv.Itoa(target.RemotePort), target.Protocol, target.Scheme, target.Path, target.RawPath, target.RawQuery,
		strings.Join(headers, "\n"), strconv.FormatBool(target.Strict), strconv.Itoa(int(timeoutSeconds)),
	}, "\x00")
}

// reusablePodResult limits result sharing to the one safe optimization: a
// Service-derived display target that copies an already-executed Pod request.
// Pod probes are deliberately never deduplicated. readiness, liveness and
// startup are independent kubelet checks and must each remain visible and be
// executed even when their URL happens to be identical.
func reusablePodResult(target Target, checkedPodTargets map[string]int) (int, bool) {
	if target.Group != "service" {
		return 0, false
	}
	index, ok := checkedPodTargets[checkSignature(target)]
	return index, ok
}

// sharedResult copies an earlier check onto a target that resolves to the same
// destination, recording which check it came from so the report never implies
// the connection was established twice.
func sharedResult(origin Result, target Target) Result {
	shared := origin
	shared.Target = target
	shared.Shared = true
	note := fmt.Sprintf("%s :%d と同じ転送先のため、同じ接続結果です", GroupLabel(origin.Target.Group), origin.Target.RemotePort)
	if detail := strings.TrimSpace(origin.Detail); detail != "" {
		note = detail + " / " + note
	}
	shared.Detail = note
	return shared
}

// GroupLabel names a check group for humans. The service wording deliberately
// says "the port the Service forwards to" rather than anything resembling
// "the Service": every check in both groups is a port-forward straight to the
// Pod, so none of them exercises the ClusterIP, kube-proxy or the EndpointSlice
// path. What separates the groups is only where the port number came from.
func GroupLabel(group string) string {
	if group == "service" {
		return "Serviceの転送先ポート"
	}
	return "Pod直接"
}

func connectionTargetDescription(target Target, pod *corev1.Pod) string {
	protocol := strings.ToUpper(target.Protocol)
	if protocol == "" {
		protocol = "TCP"
	}
	endpoint := fmt.Sprintf("%s :%d%s", protocol, target.RemotePort, targetRequestURI(target))
	return fmt.Sprintf("Pod %s/%s の%s（%s、確認経路: %s）", pod.Namespace, pod.Name, targetName(target), endpoint, GroupLabel(target.Group))
}

func (checker *Checker) checkOne(ctx context.Context, pod *corev1.Pod, target Target, local int) (Result, error) {
	result := Result{Target: target, LocalPort: local, Tested: true}
	opened, err := checker.forward(ctx, pod.Namespace, pod.Name, local, target.RemotePort)
	if err != nil {
		return result, err
	}
	cancel, ready, done, errorsFound := opened.cancel, opened.ready, opened.done, opened.errors
	// cancel is idempotent; the ctx watcher inside forward may also invoke it.
	// Waiting on done is bounded: closing stop normally unblocks ForwardPorts,
	// but a tunnel wedged inside the SPDY dial would otherwise keep this
	// deferred cleanup — and the whole diagnosis — blocked forever. Leaking the
	// goroutine is strictly better than hanging an incident-response tool.
	cleanup := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(forwardShutdownTimeout):
		}
	}
	defer cleanup()
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	case err := <-errorsFound:
		return result, err
	case <-ready:
	}
	if target.Protocol == "tcp" {
		connection, err := (&net.Dialer{Timeout: timeoutFor(target.Probe, 3*time.Second)}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(local)))
		if err != nil {
			result.Detail = withForwardReason("TCP接続に失敗しました: "+err.Error(), opened)
			return result, nil
		}
		defer connection.Close()
		reachable, detail := remoteAccepted(connection)
		result.Successful, result.Detail = reachable, detail
		if !reachable {
			result.Detail = withForwardReason(detail, opened)
		}
		return result, nil
	}
	requestURL := targetLocalURL(target, local)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return result, err
	}
	// kubelet targets the Pod IP, so net/http would normally generate a Host
	// header from PodIP:remotePort. The tunnel destination must remain local,
	// but reproducing that Host value avoids false 404/virtual-host results.
	if pod.Status.PodIP != "" {
		request.Host = defaultProbeHost(pod.Status.PodIP, target.RemotePort)
	}
	headerNames := map[string]bool{}
	for _, header := range target.Headers {
		headerNames[strings.ToLower(header.Name)] = true
		if strings.EqualFold(header.Name, "Host") {
			request.Host = header.Value
			continue
		}
		request.Header.Add(header.Name, header.Value)
	}
	if !headerNames["user-agent"] {
		request.Header.Set("User-Agent", "kube-probe/k8s-diagnose")
	}
	if !headerNames["accept"] {
		request.Header.Set("Accept", "*/*")
	}
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // #nosec G402: kubelet HTTP probes also skip certificate verification.
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeoutFor(target.Probe, 10*time.Second)}
	client.CheckRedirect = func(next *http.Request, previous []*http.Request) error {
		if len(previous) >= 10 {
			return http.ErrUseLastResponse
		}
		if next.URL.Host != previous[0].URL.Host {
			return http.ErrUseLastResponse
		}
		return nil
	}
	// requestURL is constructed above from the fixed 127.0.0.1 port-forward
	// endpoint; probe httpHeaders do not alter the network destination.
	response, err := client.Do(request) // #nosec G704 -- destination is the local typed port-forward only.
	if err != nil {
		result.Detail = "HTTP要求に失敗しました: " + err.Error()
		return result, nil
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 10*1024))
	result.StatusCode = response.StatusCode
	result.ContentType = response.Header.Get("Content-Type")
	result.BodyBytes = len(body)
	result.Proto, result.Header = response.Proto, response.Header.Clone()
	result.Body = string(body)
	if readErr != nil {
		result.Detail = "HTTP応答本文を読み取れませんでした: " + readErr.Error()
		return result, nil
	}
	result.Successful = response.StatusCode >= 200 && response.StatusCode < 400
	result.Detail = fmt.Sprintf("HTTP %d", response.StatusCode)
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		result.Warned = true
		result.Detail += "（リダイレクト応答）"
	}
	if !result.Successful && !target.Strict {
		result.Successful, result.Warned = true, true
		result.Detail += "（HTTP応答あり。Probe由来の確認ではないため、異常とは確定しません）"
	}
	return result, nil
}

// CurlCommand renders the request this target issues as a curl invocation
// against the forwarded local port, so the printed port-forward command can
// actually be followed by something. Reconstructing the scheme, path and probe
// headers by hand is the tedious part of reproducing a failed check.
//
// It mirrors checkOne exactly, including -k: the tunnel is reached as 127.0.0.1
// so a certificate issued for the Pod never matches, and the checker itself
// skips verification for the same reason kubelet does.
//
// TCP targets get nothing. There is no request to reproduce — the check is a
// bare connect, and the port-forward command already covers it.
func CurlCommand(result Result) ([]string, bool) {
	if result.Target.Protocol != "http" || result.LocalPort < 1 || result.Shared {
		return nil, false
	}
	scheme := result.Target.Scheme
	if scheme == "" {
		scheme = "http"
	}
	command := []string{"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}\\n"}
	if scheme == "https" {
		command = append(command, "-k")
	}
	// The URL goes before the headers on purpose. Printed commands are masked
	// line by line, and a credential-bearing header is masked to end of line —
	// which would swallow everything after it. Keeping the URL ahead of the
	// headers means the essential part of the command survives regardless.
	target := result.Target
	target.Scheme = scheme
	command = append(command, targetLocalURL(target, result.LocalPort))
	omitted := []string{}
	for _, header := range result.Target.Headers {
		// A probe header may carry a credential. Printing it is not acceptable
		// even masked, because the masking that protects it also truncates the
		// rest of the line and leaves an unusable command behind. Such headers
		// are dropped and named instead, so it stays obvious that the printed
		// request is not the complete one.
		if redact.IsSensitiveKey(header.Name) {
			omitted = append(omitted, header.Name)
			continue
		}
		command = append(command, "-H", header.Name+": "+header.Value)
	}
	// Any note has to come last. '#' opens a shell comment, so placing it before
	// the remaining arguments would quietly disable the headers after it.
	if len(omitted) > 0 {
		command = append(command, "#", fmt.Sprintf("%s ヘッダは値を表示しないため省略しています。実際の確認では送信しています", strings.Join(omitted, "、")))
	}
	return command, true
}

func targetLocalURL(target Target, port int) string {
	// kubelet's utilnet.FormatURL assigns HTTPGetAction.path to url.URL.Path.
	// Building a raw URL string would incorrectly treat '?' and '#' in a Probe
	// path as a query or fragment. RawPath/RawQuery remain empty for Kubernetes
	// probes and are populated only when an operator pastes a complete URL.
	scheme := target.Scheme
	if scheme == "" {
		scheme = "http"
	}
	return (&url.URL{
		Scheme:   scheme,
		Host:     net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		Path:     target.Path,
		RawPath:  target.RawPath,
		RawQuery: target.RawQuery,
	}).String()
}

func targetRequestURI(target Target) string {
	return (&url.URL{Path: target.Path, RawPath: target.RawPath, RawQuery: target.RawQuery}).RequestURI()
}

func defaultProbeHost(podIP string, port int) string {
	return net.JoinHostPort(podIP, strconv.Itoa(port))
}

func probeHost(target Target) string {
	if target.Probe == nil {
		return ""
	}
	if target.Probe.HTTPGet != nil {
		return target.Probe.HTTPGet.Host
	}
	if target.Probe.TCPSocket != nil {
		return target.Probe.TCPSocket.Host
	}
	return ""
}

func timeoutFor(probe *corev1.Probe, fallback time.Duration) time.Duration {
	if probe != nil && probe.TimeoutSeconds > 0 {
		return time.Duration(probe.TimeoutSeconds) * time.Second
	}
	return fallback
}

// portForwardTimeout bounds the SPDY upgrade round-trip so a black-holed API
// server can never hang the diagnosis indefinitely. Each tunnel carries a
// single short probe (its own timeout is <= a few seconds) and is torn down
// immediately after, so this ceiling never truncates a healthy probe; it only
// caps the pathological "connect hangs forever" case.
const portForwardTimeout = 30 * time.Second

// forwardShutdownTimeout bounds how long cleanup waits for ForwardPorts to
// return after the tunnel is cancelled. Teardown is normally immediate; this
// only caps the pathological case where the forwarder never returns.
const forwardShutdownTimeout = 5 * time.Second

// forward opens a port-forward tunnel. It honours ctx: cancellation or deadline
// closes the tunnel and unblocks ForwardPorts. The returned cancel func is
// idempotent (guarded by sync.Once) and is the single owner of the stop signal,
// so the ctx watcher here and the caller's cleanup can both invoke it safely.
// remoteSettleTimeout bounds how long a TCP check waits to see whether the
// tunnel stays open. A container port that is refused is dropped as soon as
// kubelet answers, so this only has to cover one round trip to the API server;
// a port that is genuinely listening simply waits, and that wait is the success.
const remoteSettleTimeout = 2 * time.Second

// remoteAccepted decides whether anything is actually listening on the far side
// of a port-forward.
//
// Dialing the local port proves nothing: the forwarder binds and accepts the
// local connection before it ever asks kubelet to reach the container, so a
// refused container port still produces a successful Dial. That is exactly the
// "the tunnel is up but nothing answers" case, and treating Dial as the answer
// reports it as a healthy connection.
//
// Reading tells them apart. If kubelet could not reach the port the forwarder
// tears the connection down and the read returns at once with EOF or a reset.
// A listening server usually says nothing until spoken to, so a read that
// simply times out with the connection still open is the success signal — and
// a server that greets first (SMTP, Redis, databases) returns its banner.
func remoteAccepted(connection net.Conn) (bool, string) {
	if err := connection.SetReadDeadline(time.Now().Add(remoteSettleTimeout)); err != nil {
		return true, "TCP接続成立（読み取り期限を設定できないため、接続確立のみで判定しました）"
	}
	buffer := make([]byte, 1)
	read, err := connection.Read(buffer)
	switch {
	case read > 0:
		return true, "TCP接続成立（接続直後に応答データを受信）"
	case err == nil:
		return true, "TCP接続成立"
	case errors.Is(err, os.ErrDeadlineExceeded):
		// Still open after the wait: the far side accepted and is waiting for a
		// request, which is what a healthy TCP service looks like.
		return true, "TCP接続成立（接続を維持したまま要求待ち）"
	case errors.Is(err, io.EOF):
		return false, "port-forwardのトンネルは確立しましたが、転送先のコンテナがポートで待ち受けていないため接続が切断されました"
	default:
		return false, "port-forwardのトンネルは確立しましたが、転送先への接続が確立できませんでした: " + err.Error()
	}
}

// withForwardReason appends whatever the forwarder itself reported. kubelet's
// refusal is written to that log rather than returned, and it names the port and
// the reason far more precisely than a local read error ever can.
func withForwardReason(detail string, opened *tunnel) string {
	reason := opened.log.String()
	if reason == "" {
		return detail
	}
	return detail + "。port-forwardの報告: " + redact.SanitizeText(reason)
}

// forwardLog captures what the port-forwarder reports about a tunnel. kubelet
// refusing the container port is written here rather than returned as an error,
// so discarding this output is what makes a refused port look like a healthy
// one. It is written from the forwarder's goroutine while the check reads it,
// hence the mutex.
type forwardLog struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (l *forwardLog) Write(value []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.Write(value)
}

func (l *forwardLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.TrimSpace(l.buffer.String())
}

// tunnel is one open port-forward and everything needed to judge and close it.
type tunnel struct {
	cancel func()
	ready  chan struct{}
	done   chan struct{}
	errors chan error
	log    *forwardLog
}

func (checker *Checker) forward(ctx context.Context, namespace, pod string, local, remote int) (*tunnel, error) {
	transport, upgrader, err := transportspdy.RoundTripperFor(checker.Clients.RESTConfig)
	if err != nil {
		return nil, err
	}
	hostURL, err := checker.portForwardURL(namespace, pod)
	if err != nil {
		return nil, err
	}
	dialer := transportspdy.NewDialer(upgrader, &http.Client{Transport: transport, Timeout: portForwardTimeout}, http.MethodPost, hostURL)
	stop, ready, done, errorsFound := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	opened := &tunnel{
		cancel: func() { once.Do(func() { close(stop) }) },
		ready:  ready, done: done, errors: errorsFound, log: &forwardLog{},
	}
	forwarder, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{fmt.Sprintf("%d:%d", local, remote)}, stop, ready, io.Discard, opened.log)
	if err != nil {
		return nil, err
	}
	go func() {
		defer close(done)
		if err := forwarder.ForwardPorts(); err != nil {
			errorsFound <- err
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			opened.cancel()
		case <-done:
		}
	}()
	return opened, nil
}

func (checker *Checker) portForwardURL(namespace, pod string) (*url.URL, error) {
	// Preserve a path prefix used by API gateways such as Rancher. namespace and
	// Pod names are Kubernetes DNS labels and therefore contain no path slash.
	hostURL, err := url.Parse(checker.Clients.RESTConfig.Host)
	if err != nil {
		return nil, err
	}
	hostURL.Path = strings.TrimRight(hostURL.Path, "/") + fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", namespace, pod)
	return hostURL, nil
}
