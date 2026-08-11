package connect

import (
	"fmt"
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
		t.Fatal("Service指定Podの確認対象がない")
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
	raw := localProbeURL("http", 8080, "/ready?full=true#detail")
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
