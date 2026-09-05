package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodLevelRequestsSuppressContainerRequestCandidate(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-budget", Namespace: "ns"},
		Spec: corev1.PodSpec{
			Resources: &corev1.ResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("256Mi"),
			}},
			Containers: []corev1.Container{{Name: "app", Image: "example/app:v1", LivenessProbe: &corev1.Probe{}}},
		},
	}
	findings := (ConfigRiskRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, config.Defaults())
	if hasCodeAndResource(findings, "K8S.CONFIG.REQUESTS_MISSING", "Pod/ns/shared-budget") {
		t.Fatalf("Pod-level requestsがある正常構成を誤検知した: %#v", findings)
	}
}

func TestImagePullSecretMissingIsWarningButMountedSecretIsIssue(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			ImagePullSecrets:   []corev1.LocalObjectReference{{Name: "registry"}},
			Containers:         []corev1.Container{{Name: "app"}},
		},
	}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns"}}}}
	findings := (DependencyRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if len(findings) != 1 || findings[0].Code != "K8S.DEPENDENCY.MISSING_IMAGE_PULL_SECRET" || findings[0].Severity != model.Warning {
		t.Fatalf("欠落imagePullSecretを警告として扱っていない: %#v", findings)
	}
	pod.Spec.Volumes = []corev1.Volume{{Name: "credentials", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "registry"}}}}
	snapshot.Pods = []corev1.Pod{pod}
	findings = (DependencyRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasSeverityCode(findings, model.Issue, "K8S.DEPENDENCY.MISSING_OBJECT") {
		t.Fatalf("同じSecretの必須volume参照がimagePull警告に降格された: %#v", findings)
	}
}

func TestEphemeralContainerFailureDoesNotBecomePodIssue(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Status: corev1.PodStatus{
			Phase:                      corev1.PodRunning,
			Conditions:                 []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			EphemeralContainerStatuses: []corev1.ContainerStatus{{Name: "debug", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137}}}},
		},
	}
	findings := (PodHealthRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, config.Defaults())
	if hasSeverityCode(findings, model.Issue, "K8S.POD.ABNORMAL_STATE") {
		t.Fatalf("ephemeral containerの終了をPod確定異常にした: %#v", findings)
	}
}

func TestBareFailedPodIsIssueButFailedJobAttemptIsNot(t *testing.T) {
	failed := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "one-shot", Namespace: "ns"}, Status: corev1.PodStatus{Phase: corev1.PodFailed, Reason: "Evicted", Message: "disk pressure"}}
	jobAttempt := failed
	jobAttempt.Name = "job-attempt"
	controller := true
	jobAttempt.OwnerReferences = []metav1.OwnerReference{{Kind: "Job", Name: "batch", Controller: &controller}}
	findings := (PodHealthRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{failed, jobAttempt}}, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.POD.FAILED_PHASE", "Pod/ns/one-shot") || hasCodeAndResource(findings, "K8S.POD.FAILED_PHASE", "Pod/ns/job-attempt") {
		t.Fatalf("bare Pod失敗とJob retry attemptを区別できない: %#v", findings)
	}
}

func TestTerminalPodTeardownDoesNotReportSandboxNotReady(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodSucceeded, corev1.PodFailed} {
		t.Run(string(phase), func(t *testing.T) {
			pod := corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "job-attempt", Namespace: "ns"},
				Status: corev1.PodStatus{
					Phase: phase,
					Conditions: []corev1.PodCondition{{
						Type: corev1.PodReadyToStartContainers, Status: corev1.ConditionFalse,
					}},
				},
			}
			findings := (PodHealthRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, config.Defaults())
			if hasFindingCode(findings, "K8S.POD.SANDBOX_NOT_READY") {
				t.Fatalf("終了済みPodの通常のsandbox破棄を異常扱いした: %#v", findings)
			}
		})
	}
}

func TestEphemeralContainerDependencyDoesNotBecomePodIssueOrImpact(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
			EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name: "debug", Env: []corev1.EnvVar{{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "debug-secret"}, Key: "token"}}}},
			}}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, ServiceAccounts: []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns"}}}}
	findings := (DependencyRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if len(findings) != 1 || findings[0].Severity != model.Warning || findings[0].Code != "K8S.DEPENDENCY.EPHEMERAL_MISSING_OBJECT" {
		t.Fatalf("Ephemeral Container依存をPod確定異常にした: %#v", findings)
	}
	state := model.NewState()
	state.Add(findings[0])
	Correlate(&kube.Snapshot{Pods: []corev1.Pod{pod}}, state)
	if len(state.RootCauses) != 0 {
		t.Fatalf("Ephemeral Container依存をPodへ波及させた: %#v", state.RootCauses)
	}
}

func TestPreviousOOMKilledIsReportedEvenBelowRestartThreshold(t *testing.T) {
	serverTime := time.Date(2035, 1, 1, 12, 0, 0, 0, time.UTC)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", RestartCount: 1, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137, FinishedAt: metav1.NewTime(serverTime.Add(-time.Hour))}},
		}}},
	}
	findings := (PodHealthRule{}).Evaluate(context.Background(), &kube.Snapshot{ServerTime: serverTime, Pods: []corev1.Pod{pod}}, config.Defaults())
	if !hasSeverityCode(findings, model.Warning, "K8S.POD.PREVIOUS_OOM_KILLED") {
		t.Fatalf("直近OOMKilledを閾値未満として見落とした: %#v", findings)
	}
}

func TestAgeAndTLSRulesUseAPIServerTime(t *testing.T) {
	serverTime := time.Date(2035, 1, 1, 12, 0, 0, 0, time.UTC)
	deletion := metav1.NewTime(serverTime.Add(-6 * time.Minute))
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns", DeletionTimestamp: &deletion}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	snapshot := &kube.Snapshot{ServerTime: serverTime, Pods: []corev1.Pod{pod}}
	if findings := (PodHealthRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); !hasSeverityCode(findings, model.Warning, "K8S.POD.TERMINATING_STATE") {
		t.Fatalf("API Server時刻基準のTerminating判定が働かない: %#v", findings)
	}
	cert := certificatePEM(t, serverTime.Add(10*24*time.Hour), 9001)
	tlsSnapshot := &kube.Snapshot{ServerTime: serverTime, Secrets: []kube.SecretProjection{{Namespace: "ns", Name: "tls", Type: corev1.SecretTypeTLS, TLSCert: cert}}}
	if findings := (TLSRule{}).Evaluate(context.Background(), tlsSnapshot, config.Defaults()); !hasSeverityCode(findings, model.Warning, "K8S.TLS.CERT_EXPIRING_SOON") {
		t.Fatalf("TLS期限判定がAPI Server時刻を使っていない: %#v", findings)
	}
}

func TestTLSBundleRejectsTrailingGarbage(t *testing.T) {
	data := append(certificatePEM(t, time.Now().Add(24*time.Hour), 9002), []byte("\nnot-a-pem\n")...)
	snapshot := &kube.Snapshot{Secrets: []kube.SecretProjection{{Namespace: "ns", Name: "tls", Type: corev1.SecretTypeTLS, TLSCert: data}}}
	findings := (TLSRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasSeverityCode(findings, model.Issue, "K8S.TLS.CERT_INVALID") {
		t.Fatalf("証明書後方の壊れたデータを見落とした: %#v", findings)
	}
}

func TestTLSMissingDataAndFutureNotBeforeAreIssues(t *testing.T) {
	serverTime := time.Date(2035, 1, 1, 12, 0, 0, 0, time.UTC)
	future := certificatePEMWindow(t, serverTime.Add(time.Hour), serverTime.Add(48*time.Hour), 9003)
	snapshot := &kube.Snapshot{ServerTime: serverTime, Secrets: []kube.SecretProjection{
		{Namespace: "ns", Name: "empty", Type: corev1.SecretTypeTLS, Keys: map[string]struct{}{}},
		{Namespace: "ns", Name: "future", Type: corev1.SecretTypeTLS, TLSCert: future, Keys: map[string]struct{}{corev1.TLSCertKey: {}, corev1.TLSPrivateKeyKey: {}}},
	}}
	findings := (TLSRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.TLS.SECRET_DATA_MISSING", "Secret/ns/empty") || !hasCodeAndResource(findings, "K8S.TLS.CERT_NOT_YET_VALID", "Secret/ns/future") {
		t.Fatalf("TLS Secret欠落またはNotBeforeを検出できない: %#v", findings)
	}
}

func TestIngressTLSSecretRequiresConventionalKeysRegardlessOfType(t *testing.T) {
	ingress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns"},
		Spec:       networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{SecretName: "opaque-tls"}}},
	}
	snapshot := &kube.Snapshot{
		Ingresses: []networkingv1.Ingress{ingress},
		Secrets:   []kube.SecretProjection{{Namespace: "ns", Name: "opaque-tls", Type: corev1.SecretTypeOpaque, Keys: map[string]struct{}{corev1.TLSCertKey: {}}}},
	}
	findings := (IngressRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.INGRESS.INVALID_TLS_SECRET", "Ingress/ns/web") {
		t.Fatalf("Ingress TLS Secretのtls.key欠落を検出できない: %#v", findings)
	}
}

func TestLogSignatureINIRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signatures.ini")
	data := "[signature.custom]\npattern = panic\npattern = fatal\ntitle = duplicate\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLogAnalyzer(path, 100); err == nil {
		t.Fatal("重複キーを持つログシグネチャINIを受理した")
	}
}

func TestLogSignatureINIRejectsOversizedTitle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signatures.ini")
	data := "[signature.custom]\npattern = panic\ntitle = " + strings.Repeat("長", 501) + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLogAnalyzer(path, 100); err == nil {
		t.Fatal("500文字を超えるログシグネチャtitleを受理した")
	}
}

func hasSeverityCode(findings []model.Finding, severity model.Severity, code string) bool {
	for _, finding := range findings {
		if finding.Severity == severity && finding.Code == code {
			return true
		}
	}
	return false
}
