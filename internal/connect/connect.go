// Package connect reproduces Pod HTTP/TCP probes through client-go port-forwarding.
package connect

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/portforward"
	transportspdy "k8s.io/client-go/transport/spdy"
)

type Target struct {
	Container   string
	ProbeType   string
	Group       string
	Label       string
	Protocol    string
	RemotePort  int
	PortName    string
	Path        string
	Scheme      string
	Headers     []corev1.HTTPHeader
	Probe       *corev1.Probe
	Source      string
	Strict      bool
	Active      bool
	Unavailable bool
	Invalid     bool
	Inactive    string
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
						Strict: true, Invalid: true, Inactive: fmt.Sprintf("名前付きport %qをcontainerPortへ解決できません", get.Port.StrVal),
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
					inactive = fmt.Sprintf("httpGet.host=%q の接続先はport-forwardでは再現できません", get.Host)
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
					result = append(result, Target{Container: container.Name, ProbeType: value.name, Group: "pod", Label: value.name, Protocol: "tcp", PortName: tcp.Port.StrVal, Probe: value.probe, Source: "probe", Strict: true, Invalid: true, Inactive: fmt.Sprintf("名前付きport %qをcontainerPortへ解決できません", tcp.Port.StrVal)})
				} else {
					active, inactive := probeActive(pod, container.Name, value.name, value.probe, now)
					unavailable := false
					if active && tcp.Host != "" {
						active = false
						unavailable = true
						inactive = fmt.Sprintf("tcpSocket.host=%q の接続先はport-forwardでは再現できません", tcp.Host)
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
			target := Target{Group: "service", Label: fmt.Sprintf("svc/%s :%d→%s", service.Name, servicePort.Port, targetText), Protocol: "tcp", RemotePort: remote, PortName: targetName, Source: "service", Strict: false, Active: true}
			for _, probeTarget := range podTargets {
				if probeTarget.Source != "probe" || probeTarget.Protocol != "http" || !probeTarget.Active {
					continue
				}
				if probeTarget.RemotePort == remote || targetName != "" && probeTarget.PortName == targetName {
					target.Container, target.ProbeType = probeTarget.Container, probeTarget.ProbeType
					target.Protocol, target.Path, target.Scheme = "http", probeTarget.Path, probeTarget.Scheme
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
		return false, "コンテナがRunningではありません"
	}
	if probeType == "startupProbe" && status.Started != nil && *status.Started {
		return false, "startupProbe成功済み"
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
			return false, "startupProbe完了待ち"
		}
	}
	if probe.InitialDelaySeconds > 0 && now.Sub(status.State.Running.StartedAt.Time) < time.Duration(probe.InitialDelaySeconds)*time.Second {
		return false, "initialDelaySeconds内"
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
	for _, target := range targets {
		if !target.Active {
			results = append(results, Result{Target: target, Detail: "未実施: " + target.Inactive})
			if target.Invalid {
				findings = append(findings, model.NewFinding(model.Issue, "K8S.PROBE.PORT_UNRESOLVED", "Probe", targetResource(target, pod), "NamedPortUnresolved", probePortStableKey(target), fmt.Sprintf("Pod %s/%s / container %s: %sの名前付きport %qをcontainerPortへ解決できません", pod.Namespace, pod.Name, target.Container, targetName(target), target.PortName), 100,
					model.Evidence{Kind: "probe", Key: "portName", Value: target.PortName},
				))
			} else if target.Unavailable {
				findings = append(findings, model.NewFinding(model.Unavailable, "K8S.CONNECT.PROBE_HOST_UNSUPPORTED", "Probe確認", targetResource(target, pod), "ProbeHostNotReproduced", target.Group+"/"+targetName(target)+"/host", fmt.Sprintf("%s %s/%s: %s は接続先host指定をport-forwardで再現できないため未実施です (%s)", groupLabel(target.Group), pod.Namespace, pod.Name, targetName(target), target.Inactive), 100,
					model.Evidence{Kind: "probe", Key: "host", Value: probeHost(target)},
				))
			}
			continue
		}
		local := base + offset
		offset++
		if local > 65535 {
			results = append(results, Result{Target: target, LocalPort: local, Detail: "ローカルポート範囲外"})
			findings = append(findings, model.NewFinding(model.Unavailable, "K8S.CONNECT.LOCAL_PORT_UNAVAILABLE", "接続確認", "Pod/"+pod.Namespace+"/"+pod.Name, "LocalPortRange", target.Group+"/local-port-range", fmt.Sprintf("ローカルポート %d は65535を超えるため確認できません", local), 100))
			continue
		}
		result, err := checker.checkOne(ctx, pod, target, local)
		results = append(results, result)
		if err != nil {
			results[len(results)-1].Tested = false
			findings = append(findings, model.NewFinding(model.Unavailable, "K8S.CONNECT.PORT_FORWARD_UNAVAILABLE", "接続確認", targetResource(target, pod), "PortForwardFailed", target.Group+"/"+targetName(target)+"/"+strconv.Itoa(target.RemotePort), fmt.Sprintf("%s %s/%s: %s :%dの接続確認を実施できません (%v)", groupLabel(target.Group), pod.Namespace, pod.Name, targetName(target), target.RemotePort, err), 100))
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
			findings = append(findings, model.NewFinding(model.Warning, code, section, targetResource(target, pod), targetName(target), target.Group+"/"+targetName(target)+"/"+strconv.Itoa(target.RemotePort), fmt.Sprintf("%s %s/%s: %s :%d%s の単発模擬確認が失敗しました (%s)", groupLabel(target.Group), pod.Namespace, pod.Name, targetName(target), target.RemotePort, target.Path, result.Detail), confidence,
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
			findings = append(findings, model.NewFinding(model.Warning, "K8S.CONNECT.HTTP_RESPONSE_WARNING", "接続確認", targetResource(target, pod), "HTTPResponseWarning", target.Group+"/"+targetName(target)+"/"+strconv.Itoa(target.RemotePort), fmt.Sprintf("%s %s/%s: :%d%sは応答しましたが注意が必要です (%s)", groupLabel(target.Group), pod.Namespace, pod.Name, target.RemotePort, target.Path, result.Detail), 60, connectEvidence(result)...))
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

func groupLabel(group string) string {
	if group == "service" {
		return "Service指定Pod"
	}
	return "Pod直接"
}

func (checker *Checker) checkOne(ctx context.Context, pod *corev1.Pod, target Target, local int) (Result, error) {
	result := Result{Target: target, LocalPort: local, Tested: true}
	stop, ready, done, errorsFound, err := checker.forward(ctx, pod.Namespace, pod.Name, local, target.RemotePort)
	if err != nil {
		return result, err
	}
	var once sync.Once
	cleanup := func() { once.Do(func() { close(stop); <-done }) }
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
			result.Detail = err.Error()
			return result, nil
		}
		_ = connection.Close()
		result.Successful, result.Detail = true, "TCP接続成立"
		return result, nil
	}
	requestURL := localProbeURL(target.Scheme, local, target.Path)
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
		result.Detail = err.Error()
		return result, nil
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 10*1024))
	result.StatusCode = response.StatusCode
	result.ContentType = response.Header.Get("Content-Type")
	result.BodyBytes = len(body)
	result.Body = string(body)
	if readErr != nil {
		result.Detail = readErr.Error()
		return result, nil
	}
	result.Successful = response.StatusCode >= 200 && response.StatusCode < 400
	result.Detail = fmt.Sprintf("HTTP %d", response.StatusCode)
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		result.Warned = true
		result.Detail += " (redirect応答)"
	}
	if !result.Successful && !target.Strict {
		result.Successful, result.Warned = true, true
		result.Detail += " (HTTP応答あり、probe由来でないため異常確定せず)"
	}
	return result, nil
}

func localProbeURL(scheme string, port int, path string) string {
	// kubelet's utilnet.FormatURL assigns HTTPGetAction.path to url.URL.Path.
	// Building a raw URL string would incorrectly treat '?' and '#' in that
	// field as a query or fragment instead of escaped path characters.
	return (&url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		Path:   path,
	}).String()
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

func (checker *Checker) forward(_ context.Context, namespace, pod string, local, remote int) (chan struct{}, chan struct{}, chan struct{}, chan error, error) {
	transport, upgrader, err := transportspdy.RoundTripperFor(checker.Clients.RESTConfig)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	hostURL, err := checker.portForwardURL(namespace, pod)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	dialer := transportspdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, hostURL)
	stop, ready, done, errorsFound := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan error, 1)
	forwarder, err := portforward.NewOnAddresses(dialer, []string{"127.0.0.1"}, []string{fmt.Sprintf("%d:%d", local, remote)}, stop, ready, io.Discard, &bytes.Buffer{})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	go func() {
		defer close(done)
		if err := forwarder.ForwardPorts(); err != nil {
			errorsFound <- err
		}
	}()
	return stop, ready, done, errorsFound, nil
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
