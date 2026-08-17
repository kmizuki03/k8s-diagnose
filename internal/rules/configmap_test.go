package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func configMapSnapshot(pod corev1.Pod, configMaps ...corev1.ConfigMap) *kube.Snapshot {
	snapshot := kube.NewSnapshot()
	snapshot.Pods = []corev1.Pod{pod}
	snapshot.ConfigMaps = configMaps
	for _, key := range []string{"pods", "configmaps"} {
		snapshot.Statuses[key] = kube.FetchStatus{Available: true}
	}
	return snapshot
}

func configMapPod(spec corev1.PodSpec) corev1.Pod {
	spec.Containers[0].Name = "app"
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "ns"},
		Spec:       spec,
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
		},
	}
}

func envFromConfigMap(prefix, name string) corev1.PodSpec {
	return corev1.PodSpec{Containers: []corev1.Container{{
		EnvFrom: []corev1.EnvFromSource{{Prefix: prefix, ConfigMapRef: &corev1.ConfigMapEnvSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: name},
		}}},
	}}}
}

// RelaxedEnvironmentVariableValidation is GA in the Kubernetes version this
// module targets. A ConfigMap Data key beginning with a digit is therefore a
// real envFrom variable and must participate in precedence analysis rather than
// being reported as invalid or silently skipped by this tool.
func TestConfigMapEnvFromAcceptsDigitLeadingDataKey(t *testing.T) {
	snapshot := configMapSnapshot(
		configMapPod(twoConfigMapEnvFrom("base", "overlay")),
		configMapWith("base", map[string]string{"2fa_secret": "old"}),
		configMapWith("overlay", map[string]string{"2fa_secret": "new"}),
	)
	findings := (ConfigMapRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.CONFIGMAP.ENV_KEY_SHADOWED", "ConfigMap/ns/base") {
		t.Fatalf("数字で始まる有効なenvFromキーを読み飛ばした: %#v", findings)
	}
}

// envFrom reads ConfigMap.Data, not BinaryData. Treating binaryData as an
// environment source would invent a collision that kubelet never observes.
func TestConfigMapBinaryDataDoesNotBecomeEnvFromVariable(t *testing.T) {
	snapshot := configMapSnapshot(
		configMapPod(twoConfigMapEnvFrom("base", "overlay")),
		corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "base", Namespace: "ns"},
			BinaryData: map[string][]byte{"LOG_LEVEL": []byte("debug")},
		},
		configMapWith("overlay", map[string]string{"LOG_LEVEL": "info"}),
	)
	findings := (ConfigMapRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if hasCodeAndResource(findings, "K8S.CONFIGMAP.ENV_KEY_SHADOWED", "ConfigMap/ns/base") {
		t.Fatalf("binaryDataをenvFromの値として誤検知した: %#v", findings)
	}
}

func TestConfigMapSubPathMountIsReportedAsCandidate(t *testing.T) {
	spec := corev1.PodSpec{
		Containers: []corev1.Container{{VolumeMounts: []corev1.VolumeMount{
			{Name: "conf", MountPath: "/etc/app.conf", SubPath: "app.conf"},
		}}},
		Volumes: []corev1.Volume{{Name: "conf", VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}},
		}}},
	}
	snapshot := configMapSnapshot(
		configMapPod(spec),
		corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "ns"}, Data: map[string]string{"app.conf": "x"}},
	)
	findings := (ConfigMapRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.CONFIGMAP.SUBPATH_NOT_UPDATED", "Pod/ns/app-1") {
		t.Fatalf("subPathマウントを検出できない: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Code != "K8S.CONFIGMAP.SUBPATH_NOT_UPDATED" {
			continue
		}
		if finding.Severity != model.Candidate {
			t.Errorf("意図的な構成もあるためCandidateであるべき: %s", finding.Severity)
		}
		if !strings.Contains(finding.Message, "設定どおり") {
			t.Errorf("意図的な場合があることが本文から読み取れない: %q", finding.Message)
		}
	}
}

// The same volume without subPath is refreshed in place by kubelet, so there is
// nothing to report.
func TestConfigMapVolumeWithoutSubPathIsNotReported(t *testing.T) {
	spec := corev1.PodSpec{
		Containers: []corev1.Container{{VolumeMounts: []corev1.VolumeMount{{Name: "conf", MountPath: "/etc/conf"}}}},
		Volumes: []corev1.Volume{{Name: "conf", VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}},
		}}},
	}
	snapshot := configMapSnapshot(
		configMapPod(spec),
		corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "ns"}, Data: map[string]string{"a": "b"}},
	)
	findings := (ConfigMapRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if hasCodeAndResource(findings, "K8S.CONFIGMAP.SUBPATH_NOT_UPDATED", "Pod/ns/app-1") {
		t.Fatalf("通常マウントを誤検知した: %#v", findings)
	}
}

func TestConfigMapSizeIsReportedOnlyNearTheObjectLimit(t *testing.T) {
	fill := func(bytes int) map[string]string {
		return map[string]string{"payload": string(make([]byte, bytes))}
	}
	near := configMapSnapshot(
		configMapPod(envFromConfigMap("", "none")),
		corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "big", Namespace: "ns"}, Data: fill(configMapObjectLimitBytes * 95 / 100)},
	)
	if !hasCodeAndResource((ConfigMapRule{}).Evaluate(context.Background(), near, config.Defaults()), "K8S.CONFIGMAP.SIZE_NEAR_LIMIT", "ConfigMap/ns/big") {
		t.Fatal("上限に接近したConfigMapを検出できない")
	}
	small := configMapSnapshot(
		configMapPod(envFromConfigMap("", "none")),
		corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "big", Namespace: "ns"}, Data: fill(1024)},
	)
	if hasCodeAndResource((ConfigMapRule{}).Evaluate(context.Background(), small, config.Defaults()), "K8S.CONFIGMAP.SIZE_NEAR_LIMIT", "ConfigMap/ns/big") {
		t.Fatal("余裕のあるConfigMapを誤検知した")
	}
}

// A missing ConfigMap is DependencyRule's finding. Reporting it here as well
// would put the same fact in two sections.
func TestConfigMapRuleLeavesMissingReferencesToTheDependencyRule(t *testing.T) {
	snapshot := configMapSnapshot(configMapPod(envFromConfigMap("", "missing")))
	if findings := (ConfigMapRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); len(findings) != 0 {
		t.Fatalf("存在しないConfigMapに対して重複した指摘を出した: %#v", findings)
	}
}

func twoConfigMapEnvFrom(first, second string) corev1.PodSpec {
	return corev1.PodSpec{Containers: []corev1.Container{{
		EnvFrom: []corev1.EnvFromSource{
			{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: first}}},
			{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: second}}},
		},
	}}}
}

func configMapWith(name string, data map[string]string) corev1.ConfigMap {
	return corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"}, Data: data}
}

// Two envFrom ConfigMaps overlapping on one key looks correct in the Pod spec:
// you have to open both ConfigMaps to see that one value never applies.
func TestConfigMapEnvKeyShadowedByALaterSourceIsReported(t *testing.T) {
	snapshot := configMapSnapshot(
		configMapPod(twoConfigMapEnvFrom("base", "overlay")),
		configMapWith("base", map[string]string{"LOG_LEVEL": "debug"}),
		configMapWith("overlay", map[string]string{"LOG_LEVEL": "info"}),
	)
	findings := (ConfigMapRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.CONFIGMAP.ENV_KEY_SHADOWED", "ConfigMap/ns/base") {
		t.Fatalf("後続のenvFromによる上書きを検出できない: %#v", findings)
	}
	// The winning ConfigMap is the one in effect, so it must not be reported.
	if hasCodeAndResource(findings, "K8S.CONFIGMAP.ENV_KEY_SHADOWED", "ConfigMap/ns/overlay") {
		t.Errorf("優先されている側まで指摘した: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Code != "K8S.CONFIGMAP.ENV_KEY_SHADOWED" {
			continue
		}
		if !strings.Contains(finding.Message, "LOG_LEVEL") || !strings.Contains(finding.Message, "overlay") {
			t.Errorf("どの変数がどこに負けたのか本文から分からない: %q", finding.Message)
		}
		if finding.Severity != model.Candidate {
			t.Errorf("意図的な上書きもあるためCandidateであるべき: %s", finding.Severity)
		}
	}
}

// Overriding a value with the same value changes nothing, so there is nothing
// for an operator to act on.
func TestConfigMapEnvKeyShadowedByAnIdenticalValueIsNotReported(t *testing.T) {
	snapshot := configMapSnapshot(
		configMapPod(twoConfigMapEnvFrom("base", "overlay")),
		configMapWith("base", map[string]string{"LOG_LEVEL": "info"}),
		configMapWith("overlay", map[string]string{"LOG_LEVEL": "info"}),
	)
	if findings := (ConfigMapRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); hasCodeAndResource(findings, "K8S.CONFIGMAP.ENV_KEY_SHADOWED", "ConfigMap/ns/base") {
		t.Fatalf("値が同じ上書きを誤検知した: %#v", findings)
	}
}

func TestConfigMapEnvKeyShadowedByAnExplicitEnvEntry(t *testing.T) {
	spec := envFromConfigMap("", "cm")
	spec.Containers[0].Env = []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "info"}}
	snapshot := configMapSnapshot(
		configMapPod(spec),
		configMapWith("cm", map[string]string{"LOG_LEVEL": "debug"}),
	)
	findings := (ConfigMapRule{}).Evaluate(context.Background(), snapshot, config.Defaults())
	if !hasCodeAndResource(findings, "K8S.CONFIGMAP.ENV_KEY_SHADOWED", "ConfigMap/ns/cm") {
		t.Fatalf("envによる上書きを検出できない: %#v", findings)
	}

	same := envFromConfigMap("", "cm")
	same.Containers[0].Env = []corev1.EnvVar{{Name: "LOG_LEVEL", Value: "debug"}}
	identical := configMapSnapshot(configMapPod(same), configMapWith("cm", map[string]string{"LOG_LEVEL": "debug"}))
	if findings := (ConfigMapRule{}).Evaluate(context.Background(), identical, config.Defaults()); hasCodeAndResource(findings, "K8S.CONFIGMAP.ENV_KEY_SHADOWED", "ConfigMap/ns/cm") {
		t.Fatalf("同じ値のenvを誤検知した: %#v", findings)
	}
}

func TestConfigMapEnvKeysWithoutCollisionAreNotReported(t *testing.T) {
	snapshot := configMapSnapshot(
		configMapPod(twoConfigMapEnvFrom("base", "overlay")),
		configMapWith("base", map[string]string{"LOG_LEVEL": "debug"}),
		configMapWith("overlay", map[string]string{"TIMEOUT": "30"}),
	)
	if findings := (ConfigMapRule{}).Evaluate(context.Background(), snapshot, config.Defaults()); len(findings) != 0 {
		t.Fatalf("衝突していないenvFromを誤検知した: %#v", findings)
	}
}

func configMapKeyRefPod(optional bool) corev1.Pod {
	return configMapPod(corev1.PodSpec{
		Containers: []corev1.Container{{
			Env: []corev1.EnvVar{{
				Name: "CONFIG",
				ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "cm"},
					Key:                  "payload",
					Optional:             &optional,
				}},
			}},
		}},
	})
}

func dependencySnapshotForBinaryConfigMap(pod corev1.Pod) *kube.Snapshot {
	snapshot := kube.NewSnapshot()
	snapshot.Pods = []corev1.Pod{pod}
	snapshot.ConfigMaps = []corev1.ConfigMap{{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "ns"},
		BinaryData: map[string][]byte{"payload": []byte("binary")},
	}}
	snapshot.ServiceAccounts = []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns"}}}
	return snapshot
}

func TestConfigMapKeyRefDoesNotReadBinaryData(t *testing.T) {
	findings := (DependencyRule{}).Evaluate(context.Background(), dependencySnapshotForBinaryConfigMap(configMapKeyRefPod(false)), config.Defaults())
	if !hasCodeAndResource(findings, "K8S.DEPENDENCY.MISSING_KEY", "ConfigMap/ns/cm") {
		t.Fatalf("configMapKeyRefがbinaryDataを読めると誤判定した: %#v", findings)
	}
}

func TestOptionalConfigMapKeyRefReportsKeyPresentOnlyInBinaryData(t *testing.T) {
	findings := (DependencyRule{}).Evaluate(context.Background(), dependencySnapshotForBinaryConfigMap(configMapKeyRefPod(true)), config.Defaults())
	if !hasCodeAndResource(findings, "K8S.DEPENDENCY.OPTIONAL_KEY_MISSING", "ConfigMap/ns/cm") {
		t.Fatalf("optionalなconfigMapKeyRefのData欠落を見逃した: %#v", findings)
	}
}

func TestConfigMapVolumeMayProjectBinaryData(t *testing.T) {
	pod := configMapPod(corev1.PodSpec{
		Containers: []corev1.Container{{VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/config"}}}},
		Volumes: []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: "cm"},
			Items:                []corev1.KeyToPath{{Key: "payload", Path: "payload.bin"}},
		}}}},
	})
	findings := (DependencyRule{}).Evaluate(context.Background(), dependencySnapshotForBinaryConfigMap(pod), config.Defaults())
	if hasCodeAndResource(findings, "K8S.DEPENDENCY.MISSING_KEY", "ConfigMap/ns/cm") {
		t.Fatalf("volumeで利用できるbinaryDataを欠落扱いした: %#v", findings)
	}
}
