package connect

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
)

func TestTargetsKeepsAllThreeProbes(t *testing.T) {
	started := false
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"app": "api"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "api", Ports: []corev1.ContainerPort{{Name: "ready", ContainerPort: 8080}, {Name: "live", ContainerPort: 8081}, {Name: "start", ContainerPort: 8082}},
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("ready"), Path: "/ready", HTTPHeaders: []corev1.HTTPHeader{{Name: "Authorization", Value: "Basic secret"}}}}},
			LivenessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("live"), Path: "/health"}}},
			StartupProbe:   &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("start"), Path: "/startup", Scheme: corev1.URISchemeHTTPS}}},
		}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Started: &started, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}}}}},
	}
	targets := Targets(&pod, nil, "")
	probes := map[string]Target{}
	for _, target := range targets {
		if target.ProbeType != "" && target.Group == "pod" {
			probes[target.ProbeType] = target
		}
	}
	if len(probes) != 3 {
		t.Fatalf("probe数=%d, want 3: %#v", len(probes), targets)
	}
	if probes["readinessProbe"].Active || probes["livenessProbe"].Active {
		t.Fatal("startupProbe未完了中のreadiness/livenessを実施対象にした")
	}
	if !probes["startupProbe"].Active || probes["startupProbe"].Scheme != "https" {
		t.Fatalf("startupProbeのHTTPS設定が失われた: %#v", probes["startupProbe"])
	}
	if got := probes["readinessProbe"].Headers[0].Value; got != "Basic secret" {
		t.Fatalf("httpHeadersが失われた: %q", got)
	}
}

func TestFindingEvidenceNeverContainsHTTPBody(t *testing.T) {
	result := Result{StatusCode: 500, ContentType: "application/json", BodyBytes: 42, Detail: "HTTP 500", Body: `{"password":"hunter2"}`}
	joined := ""
	for _, evidence := range connectEvidence(result) {
		joined += evidence.Key + "=" + evidence.Value + "\n"
	}
	if strings.Contains(joined, "hunter2") || !strings.Contains(joined, "statusCode=500") || !strings.Contains(joined, "bodyBytesRead=42") {
		t.Fatalf("HTTP Evidenceに本文混入またはmetadata欠落: %s", joined)
	}
}

func TestPortForwardURLPreservesAPIServerPathPrefix(t *testing.T) {
	checker := Checker{Clients: &kube.Clients{RESTConfig: &rest.Config{Host: "https://cluster.example/k8s/clusters/c-123?tenant=prod&route=primary"}}}
	value, err := checker.portForwardURL("prod", "api")
	if err != nil {
		t.Fatal(err)
	}
	want := "/k8s/clusters/c-123/api/v1/namespaces/prod/pods/api/portforward"
	if value.Path != want {
		t.Fatalf("port-forward path=%q, want %q", value.Path, want)
	}
	if value.RawQuery != "tenant=prod&route=primary" {
		t.Fatalf("port-forward RawQuery=%q, want %q", value.RawQuery, "tenant=prod&route=primary")
	}
}

func TestServiceTargetsAreDistinguishedAndUseMatchedHTTPProbe(t *testing.T) {
	started := true
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "api", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}, ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("http"), Path: "/ready"}}}}}},
		Status:     corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Started: &started, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}}}}},
	}
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}, Ports: []corev1.ServicePort{{Name: "web", Port: 80, TargetPort: intstr.FromString("http")}}}}
	targets := Targets(&pod, []corev1.Service{service}, "")
	var serviceTarget *Target
	for index := range targets {
		if targets[index].Group == "service" {
			serviceTarget = &targets[index]
		}
	}
	if serviceTarget == nil {
		t.Fatal("Serviceの転送先ポートの確認対象がない")
	}
	if serviceTarget.Protocol != "http" || serviceTarget.RemotePort != 8080 || serviceTarget.Path != "/ready" {
		t.Fatalf("Serviceからprobeを引き継げていない: %#v", *serviceTarget)
	}
}

func TestNamedServicePortUsesOnlyServingContainersAndMatchingProtocol(t *testing.T) {
	restartAlways := corev1.ContainerRestartPolicyAlways
	pod := corev1.Pod{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Name: "app", Ports: []corev1.ContainerPort{
			{Name: "web", ContainerPort: 8080, Protocol: corev1.ProtocolUDP},
		}}},
		InitContainers: []corev1.Container{
			{Name: "setup", Ports: []corev1.ContainerPort{{Name: "setup-only", ContainerPort: 9000}}},
			{Name: "sidecar", RestartPolicy: &restartAlways, Ports: []corev1.ContainerPort{{Name: "metrics", ContainerPort: 9090}}},
		},
	}}

	for _, test := range []struct {
		name     string
		port     corev1.ServicePort
		wantPort int
		wantOK   bool
	}{
		{name: "ordinary init container excluded", port: corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("setup-only")}},
		{name: "restartable init sidecar included", port: corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("metrics")}, wantPort: 9090, wantOK: true},
		{name: "protocol mismatch rejected", port: corev1.ServicePort{Port: 80, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromString("web")}},
		{name: "matching UDP accepted", port: corev1.ServicePort{Port: 53, Protocol: corev1.ProtocolUDP, TargetPort: intstr.FromString("web")}, wantPort: 8080, wantOK: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, _, ok := resolveServicePort(test.port, &pod)
			if ok != test.wantOK || got != test.wantPort {
				t.Fatalf("resolveServicePort()=(%d,%v), want (%d,%v)", got, ok, test.wantPort, test.wantOK)
			}
		})
	}
}

func TestServiceInferenceDoesNotTreatUDPAsTCP(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "dns", Namespace: "ns", Labels: map[string]string{"app": "dns"}}}
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "dns", Namespace: "ns"}, Spec: corev1.ServiceSpec{
		Selector: map[string]string{"app": "dns"},
		Ports:    []corev1.ServicePort{{Port: 53, Protocol: corev1.ProtocolUDP, TargetPort: intstr.FromInt32(5353)}},
	}}
	if targets := Targets(&pod, []corev1.Service{service}, ""); len(targets) != 0 {
		t.Fatalf("UDP ServiceをTCP接続確認へ混入した: %#v", targets)
	}
}

func TestRestartableInitContainerPortIsPlainTCPCheckTarget(t *testing.T) {
	restartAlways := corev1.ContainerRestartPolicyAlways
	pod := corev1.Pod{Spec: corev1.PodSpec{InitContainers: []corev1.Container{{
		Name: "sidecar", RestartPolicy: &restartAlways,
		Ports: []corev1.ContainerPort{{Name: "metrics", ContainerPort: 9090}},
	}}}}
	targets := Targets(&pod, nil, "")
	if len(targets) != 1 || targets[0].Container != "sidecar" || targets[0].RemotePort != 9090 || targets[0].Source != "containerPort" {
		t.Fatalf("native sidecarのcontainerPortが確認対象にならない: %#v", targets)
	}
}

func TestRandomBasePortLeavesRoomForOffsets(t *testing.T) {
	for i := 0; i < 100; i++ {
		base := randomBasePort(100)
		if base < 10000 || base+99 > 65535 {
			t.Fatalf("不正なbase port: %d", base)
		}
	}
}

func TestProbeInitialDelayUsesClusterReferenceTime(t *testing.T) {
	serverTime := time.Date(2035, 2, 3, 4, 5, 6, 0, time.UTC)
	started := true
	pod := corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "api", ReadinessProbe: &corev1.Probe{
				ProbeHandler:        corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(8080), Path: "/ready"}},
				InitialDelaySeconds: 30,
			},
		}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Started: &started, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(serverTime.Add(-20 * time.Second))}}}}},
	}
	targets := targetsAt(&pod, nil, "", serverTime)
	if len(targets) != 1 || targets[0].Active || targets[0].Inactive != "initialDelaySecondsで指定された待機時間内です" {
		t.Fatalf("API Server基準のinitialDelay判定が不正: %#v", targets)
	}
	targets = targetsAt(&pod, nil, "", serverTime.Add(11*time.Second))
	if len(targets) != 1 || !targets[0].Active {
		t.Fatalf("initialDelay経過後もProbeが有効にならない: %#v", targets)
	}
}

func TestProbeDestinationHostIsUnavailableInsteadOfHostHeader(t *testing.T) {
	started := true
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "api",
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
				Host: "health.internal", Port: intstr.FromInt32(8080), Path: "/ready",
			}}},
			LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{
				Host: "database.internal", Port: intstr.FromInt32(5432),
			}}},
		}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Started: &started, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}}}}},
	}
	targets := Targets(&pod, nil, "")
	if len(targets) != 2 {
		t.Fatalf("probe数=%d, want 2: %#v", len(targets), targets)
	}
	for _, target := range targets {
		if target.Active || !target.Unavailable || !strings.Contains(target.Inactive, ".host") || !strings.Contains(target.Inactive, "port-forwardでは再現できません") {
			t.Fatalf("接続先host指定を実行対象にした: %#v", target)
		}
	}
	checker := Checker{Clients: &kube.Clients{}}
	results, findings := checker.Check(t.Context(), &pod, nil)
	if len(results) != 2 || len(findings) != 2 {
		t.Fatalf("未実施結果またはunavailable所見が不足: results=%#v findings=%#v", results, findings)
	}
	for _, finding := range findings {
		if finding.Severity != "unavailable" || finding.Code != "K8S.CONNECT.PROBE_HOST_UNSUPPORTED" {
			t.Fatalf("不正な未実施所見: %#v", finding)
		}
	}
}

func TestHTTPHeaderHostRemainsReproducible(t *testing.T) {
	started := true
	pod := corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "api", ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
				Port: intstr.FromInt32(8080), Path: "/ready", HTTPHeaders: []corev1.HTTPHeader{{Name: "Host", Value: "virtual.example"}},
			}}},
		}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Started: &started, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}}}}},
	}
	targets := Targets(&pod, nil, "")
	if len(targets) != 1 || !targets[0].Active || targets[0].Unavailable {
		t.Fatalf("httpHeadersのHostを接続先hostと誤認した: %#v", targets)
	}
	if len(targets[0].Headers) != 1 || targets[0].Headers[0].Value != "virtual.example" {
		t.Fatalf("Host headerが失われた: %#v", targets[0].Headers)
	}
}

func TestKubeletDefaultHostHeaderShape(t *testing.T) {
	for _, test := range []struct {
		podIP string
		want  string
	}{
		{"10.0.0.8", "10.0.0.8:8080"},
		{"2001:db8::8", "[2001:db8::8]:8080"},
	} {
		if got := defaultProbeHost(test.podIP, 8080); got != test.want {
			t.Fatalf("Pod IP由来Host=%q, want %q", got, test.want)
		}
	}
}

func TestProbePathQuestionAndFragmentRemainPathCharacters(t *testing.T) {
	raw := targetLocalURL(Target{Scheme: "http", Path: "/ready?full=true#detail"}, 8080)
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Path != "/ready?full=true#detail" || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatalf("HTTPGet.pathをquery/fragmentへ誤分解した: raw=%q parsed=%#v", raw, parsed)
	}
	if !strings.Contains(raw, "%3F") || !strings.Contains(raw, "%23") {
		t.Fatalf("HTTPGet.pathの特殊文字がURL pathとしてescapeされない: %q", raw)
	}
}

func TestDefaultProbePathOverrideKeepsStrictStatusEvaluation(t *testing.T) {
	started := true
	pod := corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "api", ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(8080)}}},
		}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Started: &started, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}}}}},
	}
	targets := Targets(&pod, nil, "/")
	if len(targets) != 1 || targets[0].Path != "/" || !targets[0].Strict {
		t.Fatalf("既定pathと等価なoverrideを緩いHTTP確認へ降格した: %#v", targets)
	}
}

func TestUnresolvedNamedProbePortIsExplicitIssue(t *testing.T) {
	started := true
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "api", ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("missing"), Path: "/ready"}}},
		}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Started: &started, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}}}}},
	}
	targets := Targets(&pod, nil, "")
	if len(targets) != 1 || !targets[0].Invalid || targets[0].Active || targets[0].PortName != "missing" {
		t.Fatalf("解決不能Probeが接続対象から無言で消えた: %#v", targets)
	}
	results, findings := (&Checker{Clients: &kube.Clients{}}).Check(t.Context(), &pod, nil)
	if len(results) != 1 || len(findings) != 1 || findings[0].Code != "K8S.PROBE.PORT_UNRESOLVED" || findings[0].Severity != "issue" {
		t.Fatalf("解決不能Probeの結果またはFindingが不正: results=%#v findings=%#v", results, findings)
	}
	for _, want := range []string{
		"コンテナ \"api\" に設定された readinessProbe",
		"ポート \"missing\" を解決できません",
		"同じコンテナの ports[].name には、\"missing\" が定義されていません",
	} {
		if !strings.Contains(findings[0].Message, want) {
			t.Fatalf("Probeポート不一致の説明に%qがない: %q", want, findings[0].Message)
		}
	}
	evidence := fmt.Sprint(findings[0].Evidence)
	for _, want := range []string{
		"readinessProbe.port: \"missing\"",
		"コンテナ \"api\" の ports[].name に定義された名前: なし",
		"ポート名 \"missing\" に対応する containerPort は見つかりませんでした（0件）",
	} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("Probeポート不一致の根拠に%qがない: %#v", want, findings[0].Evidence)
		}
	}
}

func TestConnectionTargetDescriptionIsReadable(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}}
	target := Target{Group: "pod", ProbeType: "readinessProbe", Protocol: "http", RemotePort: 8080, Path: "/ready"}
	got := connectionTargetDescription(target, pod)
	for _, want := range []string{"Pod ns/api のreadinessProbe", "HTTP :8080/ready", "確認経路: Pod直接"} {
		if !strings.Contains(got, want) {
			t.Fatalf("接続先の説明に%qがありません: %q", want, got)
		}
	}
	if strings.Contains(got, ": :") {
		t.Fatalf("接続先の説明に二重のコロンが残っています: %q", got)
	}
}

func targetsForServicePort(target int32) []Target {
	started := true
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns", Labels: map[string]string{"app": "api"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  "api",
			Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromInt32(8080), Path: "/ready"},
			}},
		}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "api", Started: &started, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Now().Add(-time.Hour))}}}}},
	}
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "api"},
			Ports:    []corev1.ServicePort{{Name: "web", Port: 80, TargetPort: intstr.FromInt32(target)}},
		},
	}
	return Targets(&pod, []corev1.Service{service}, "")
}

func groupedTarget(targets []Target, group string) Target {
	for _, target := range targets {
		if target.Group == group {
			return target
		}
	}
	return Target{}
}

// A Service that resolves onto the port the Pod group already checks leaves
// nothing to compare, so the two targets must collapse onto one port-forward.
// A Service pointing somewhere else is the case the two groups exist for and
// must keep its own check — that difference is the targetPort diagnosis.
func TestOnlyIdenticalDestinationsShareOneCheck(t *testing.T) {
	same := targetsForServicePort(8080)
	if checkSignature(groupedTarget(same, "pod")) != checkSignature(groupedTarget(same, "service")) {
		t.Fatalf("同一の転送先が共有されない: pod=%#v service=%#v", groupedTarget(same, "pod"), groupedTarget(same, "service"))
	}
	differs := targetsForServicePort(8081)
	if checkSignature(groupedTarget(differs, "pod")) == checkSignature(groupedTarget(differs, "service")) {
		t.Fatal("転送先が異なるのに共有された。targetPort不一致を検出できなくなる")
	}
}

func TestProbeChecksAreNeverCollapsedIntoEachOther(t *testing.T) {
	target := Target{Group: "pod", Protocol: "http", Scheme: "http", RemotePort: 8080, Path: "/health", Strict: true}
	checked := map[string]int{checkSignature(target): 3}
	if _, shared := reusablePodResult(target, checked); shared {
		t.Fatal("同じURLのPod Probeを独立実行せず共有した")
	}
	service := target
	service.Group = "service"
	if index, shared := reusablePodResult(service, checked); !shared || index != 3 {
		t.Fatalf("同一リクエストを使うService表示でPod結果を再利用できない: shared=%v index=%d", shared, index)
	}
}

func TestCheckSignatureIncludesProbeDecisionInputs(t *testing.T) {
	base := Target{
		Group: "pod", Protocol: "http", Scheme: "http", RemotePort: 8080,
		Path: "/health", Strict: true, Probe: &corev1.Probe{TimeoutSeconds: 1},
	}
	longTimeout := base
	longTimeout.Probe = &corev1.Probe{TimeoutSeconds: 10}
	if checkSignature(base) == checkSignature(longTimeout) {
		t.Fatal("timeoutSecondsが異なるProbeを同じ接続結果として扱った")
	}
	nonStrict := base
	nonStrict.Strict = false
	if checkSignature(base) == checkSignature(nonStrict) {
		t.Fatal("HTTPステータスの厳格判定が異なる対象を同一視した")
	}
}

func TestSharedResultReportsBothGroupsWithoutClaimingASecondConnection(t *testing.T) {
	targets := targetsForServicePort(8080)
	origin := Result{Target: groupedTarget(targets, "pod"), LocalPort: 16081, Successful: true, Tested: true, StatusCode: 200, Detail: "HTTP 200"}
	shared := sharedResult(origin, groupedTarget(targets, "service"))
	if !shared.Shared {
		t.Fatal("共有結果に印が付いていない")
	}
	if shared.Target.Group != "service" {
		t.Fatalf("共有先のグループが失われた: %q", shared.Target.Group)
	}
	if !shared.Successful || shared.StatusCode != origin.StatusCode {
		t.Fatalf("元の結果が引き継がれていない: %#v", shared)
	}
	if !strings.Contains(shared.Detail, "HTTP 200") || !strings.Contains(shared.Detail, "同じ転送先") {
		t.Fatalf("再利用であることが読み取れない: %q", shared.Detail)
	}
}

// port-forward always tunnels straight to the Pod, so no label may suggest that
// the Service itself — ClusterIP, kube-proxy, EndpointSlice — was exercised.
func TestGroupLabelDoesNotClaimTheServiceWasTested(t *testing.T) {
	label := GroupLabel("service")
	if strings.Contains(label, "指定Pod") || !strings.Contains(label, "転送先") {
		t.Fatalf("Service経由の疎通を検証したと誤解されうる表記: %q", label)
	}
}

func TestCurlCommandReproducesTheCheckedRequest(t *testing.T) {
	result := Result{
		LocalPort: 16081,
		Target: Target{
			Protocol: "http", Scheme: "https", Path: "/ready", RemotePort: 8080,
			Headers: []corev1.HTTPHeader{{Name: "X-Probe", Value: "kubelet"}},
		},
	}
	command, ok := CurlCommand(result)
	if !ok {
		t.Fatal("HTTP対象にcurlが出ない")
	}
	joined := strings.Join(command, " ")
	for _, want := range []string{"curl", "-k", "X-Probe: kubelet", "https://127.0.0.1:16081/ready"} {
		if !strings.Contains(joined, want) {
			t.Errorf("curlに %q が含まれない: %q", want, joined)
		}
	}
}

// The checker skips certificate verification because it reaches the Pod as
// 127.0.0.1; plain HTTP has nothing to skip and must not carry -k.
func TestCurlCommandOnlySkipsVerificationForHTTPS(t *testing.T) {
	command, ok := CurlCommand(Result{LocalPort: 16081, Target: Target{Protocol: "http", Scheme: "http", Path: "/"}})
	if !ok {
		t.Fatal("HTTP対象にcurlが出ない")
	}
	for _, arg := range command {
		if arg == "-k" {
			t.Fatalf("HTTPで証明書検証の無効化を提案している: %q", strings.Join(command, " "))
		}
	}
}

// A TCP check sends no request, and a shared result reused another target's
// tunnel — printing a command for either would suggest work that never happened.
func TestCurlCommandIsOmittedWhenThereIsNoRequestToRepeat(t *testing.T) {
	if _, ok := CurlCommand(Result{LocalPort: 16081, Target: Target{Protocol: "tcp", RemotePort: 8080}}); ok {
		t.Error("TCP確認にcurlを出している")
	}
	if _, ok := CurlCommand(Result{LocalPort: 16081, Shared: true, Target: Target{Protocol: "http", Path: "/"}}); ok {
		t.Error("共有結果に重複したcurlを出している")
	}
}

// Printed commands are masked line by line and a credential-bearing header is
// masked to end of line, which would swallow the URL and leave an unusable
// command. Such headers are dropped and named instead, and the note has to be
// last because '#' opens a shell comment that would disable anything after it.
func TestCurlCommandKeepsTheURLAndDropsCredentialHeaders(t *testing.T) {
	command, ok := CurlCommand(Result{LocalPort: 16081, Target: Target{
		Protocol: "http", Scheme: "http", Path: "/ready",
		Headers: []corev1.HTTPHeader{
			{Name: "Authorization", Value: "Bearer super-secret-token"},
			{Name: "X-Probe", Value: "kubelet"},
		},
	}})
	if !ok {
		t.Fatal("HTTP対象にcurlが出ない")
	}
	joined := strings.Join(command, " ")
	if strings.Contains(joined, "super-secret-token") {
		t.Fatalf("資格情報がコマンドに残っている: %q", joined)
	}
	urlIndex, commentIndex, headerIndex := -1, -1, -1
	for index, arg := range command {
		switch {
		case strings.HasPrefix(arg, "http://"):
			urlIndex = index
		case arg == "#":
			commentIndex = index
		case strings.HasPrefix(arg, "X-Probe:"):
			headerIndex = index
		}
	}
	if urlIndex < 0 {
		t.Fatalf("URLが失われている: %q", joined)
	}
	if headerIndex < 0 {
		t.Fatalf("機密でないヘッダまで落としている: %q", joined)
	}
	if commentIndex < 0 || commentIndex < urlIndex || commentIndex < headerIndex {
		t.Fatalf("注記が末尾にないため、以降の引数がコメント扱いで無効になる: %q", joined)
	}
}

// A port-forward listener accepts the local connection before kubelet is asked
// to reach the container, so Dial succeeding proves nothing. These cases pin
// down how the three outcomes are told apart.
func TestRemoteAcceptedDistinguishesAListenerFromADroppedTunnel(t *testing.T) {
	dialTo := func(t *testing.T, handle func(net.Conn)) net.Conn {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		go func() {
			server, err := listener.Accept()
			if err != nil {
				return
			}
			handle(server)
		}()
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client
	}

	t.Run("待ち受けているが無言のサーバは成功", func(t *testing.T) {
		connection := dialTo(t, func(server net.Conn) { time.Sleep(remoteSettleTimeout * 2); _ = server.Close() })
		if ok, detail := remoteAccepted(connection); !ok {
			t.Fatalf("待ち受け中のサーバを失敗と判定した: %s", detail)
		}
	})

	t.Run("バナーを返すサーバは成功", func(t *testing.T) {
		connection := dialTo(t, func(server net.Conn) {
			_, _ = server.Write([]byte("+OK\r\n"))
			time.Sleep(time.Second)
			_ = server.Close()
		})
		ok, detail := remoteAccepted(connection)
		if !ok {
			t.Fatalf("バナーを返すサーバを失敗と判定した: %s", detail)
		}
		if !strings.Contains(detail, "応答データ") {
			t.Errorf("応答を受信したことが分からない: %s", detail)
		}
	})

	// The forwarder drops the local connection when kubelet cannot reach the
	// container port. Before this check that case reported "TCP接続成立".
	t.Run("即座に切断されるトンネルは失敗", func(t *testing.T) {
		connection := dialTo(t, func(server net.Conn) { _ = server.Close() })
		ok, detail := remoteAccepted(connection)
		if ok {
			t.Fatalf("待ち受けていないポートを成功と判定した: %s", detail)
		}
		if !strings.Contains(detail, "待ち受けていない") {
			t.Errorf("原因が読み取れない: %s", detail)
		}
	})
}

func TestManualTargetAcceptsTheShapeOperatorsAlreadyType(t *testing.T) {
	for _, tc := range []struct {
		input    string
		protocol string
		scheme   string
		port     int
		path     string
	}{
		// A bare port stays TCP: sending HTTP to a port that speaks something
		// else would prove nothing about whether it is healthy.
		{"9000", "tcp", "", 9000, ""},
		{"8080/healthz", "http", "http", 8080, "/healthz"},
		{"https://8443/metrics", "http", "https", 8443, "/metrics"},
		{"http://8080", "http", "http", 8080, "/"},
		{"8080/", "http", "http", 8080, "/"},
		{"  8080/ready  ", "http", "http", 8080, "/ready"},
		// The URL an operator would hand to curl, pasted verbatim.
		{"http://localhost:8080/secure", "http", "http", 8080, "/secure"},
		{"https://127.0.0.1:8443/metrics", "http", "https", 8443, "/metrics"},
		{"localhost:9000", "tcp", "", 9000, ""},
		{"http://[::1]:8080/x", "http", "http", 8080, "/x"},
	} {
		target, err := ManualTarget(tc.input)
		if err != nil {
			t.Errorf("%q: %v", tc.input, err)
			continue
		}
		if target.Protocol != tc.protocol || target.Scheme != tc.scheme || target.RemotePort != tc.port || target.Path != tc.path {
			t.Errorf("%q -> protocol=%q scheme=%q port=%d path=%q", tc.input, target.Protocol, target.Scheme, target.RemotePort, target.Path)
		}
		if !target.Active || target.Group != "manual" {
			t.Errorf("%q: 手動確認として扱われていない: %#v", tc.input, target)
		}
		// An operator poking at an arbitrary endpoint is exploring, so a non-2xx
		// answer must not be reported as a confirmed cluster defect.
		if target.Strict {
			t.Errorf("%q: 手動確認がstrict判定になっている", tc.input)
		}
	}
}

func TestManualTargetRejectsWhatCannotBeChecked(t *testing.T) {
	// A non-loopback host is refused rather than ignored: quietly checking the
	// Pod after being handed another destination would answer a question nobody
	// asked.
	for _, input := range []string{"", "   ", "abc", "0", "70000", "-1", "/healthz", "https://",
		"http://user:pass@localhost:8080/x", "http://localhost:8080/x#fragment",
		"http://api.example:8080/x", "http://10.0.0.5:8080", "myservice:8080/x"} {
		if target, err := ManualTarget(input); err == nil {
			t.Errorf("%q を受理した: %#v", input, target)
		}
	}
}

func TestManualTargetPreservesQueryAndEscapedPath(t *testing.T) {
	target, err := ManualTarget("http://localhost:8080/health%2Fready?full=1&format=json")
	if err != nil {
		t.Fatal(err)
	}
	if target.Path != "/health/ready" || target.RawPath != "/health%2Fready" || target.RawQuery != "full=1&format=json" {
		t.Fatalf("貼り付けたURLの構造を保持していない: %#v", target)
	}
	got := targetLocalURL(target, 18080)
	want := "http://127.0.0.1:18080/health%2Fready?full=1&format=json"
	if got != want {
		t.Fatalf("実際に確認するURLが変化した: got=%q want=%q", got, want)
	}
	withoutPath, err := ManualTarget("8080?ready=1")
	if err != nil || withoutPath.Path != "/" || withoutPath.RawQuery != "ready=1" {
		t.Fatalf("パスなしqueryを解釈できない: target=%#v err=%v", withoutPath, err)
	}
}

func TestNextLocalPortAvoidsThePortsAlreadyBound(t *testing.T) {
	got := NextLocalPort([]Result{{LocalPort: 16081}, {LocalPort: 16083}, {LocalPort: 16082}})
	if got != 16084 {
		t.Fatalf("NextLocalPort=%d, want 16084", got)
	}
	if got := NextLocalPort(nil); got < 10000 || got > 65535 {
		t.Fatalf("結果がない場合の割当が範囲外: %d", got)
	}
}
