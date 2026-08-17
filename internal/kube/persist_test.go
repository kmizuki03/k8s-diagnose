package kube

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func supportSnapshot() *Snapshot {
	snapshot := NewSnapshot()
	snapshot.Pods = []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "api",
			Namespace:   "prod",
			Labels:      map[string]string{"app": "api"},
			Annotations: map[string]string{"bootstrap": `{"password":"annotation-secret"}`},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-1",
			Containers: []corev1.Container{{
				Name:  "api",
				Image: "example/api:1.2.3",
				Env: []corev1.EnvVar{
					{Name: "DB_PASSWORD", Value: "env-secret"},
					{Name: "LOG_LEVEL", Value: "debug"},
				},
				Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}}
	snapshot.Secrets = []SecretProjection{{
		Namespace: "prod", Name: "api-tls",
		Keys:    map[string]struct{}{"tls.crt": {}, "tls.key": {}},
		TLSCert: []byte("pretend-certificate-bytes"),
	}}
	snapshot.APIWarnings = []string{"token=warning-secret"}
	snapshot.Statuses["pods"] = FetchStatus{Available: true}
	snapshot.Statuses["nodes"] = FetchStatus{Available: false, Reason: "forbidden"}
	return snapshot
}

func supportSnapshotScope() ClusterSnapshotScope {
	return ClusterSnapshotScope{Context: "test-context", Namespace: "prod", Mode: "all"}
}

func TestClusterSnapshotRoundTripPreservesStructure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := SaveClusterSnapshot(path, "v0.1.0", supportSnapshotScope(), supportSnapshot()); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadClusterSnapshot(path)
	if err != nil {
		t.Fatalf("保存したスナップショットを読み込めない: %v", err)
	}
	if len(loaded.Pods) != 1 {
		t.Fatalf("Podが失われた: %+v", loaded.Pods)
	}
	pod := loaded.Pods[0]
	if pod.Name != "api" || pod.Namespace != "prod" || pod.Spec.NodeName != "node-1" {
		t.Fatalf("Pod識別情報が失われた: %+v", pod.ObjectMeta)
	}
	if len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Image != "example/api:1.2.3" {
		t.Fatalf("コンテナ情報が失われた: %+v", pod.Spec.Containers)
	}
	if len(pod.Spec.Containers[0].Ports) != 1 || pod.Spec.Containers[0].Ports[0].ContainerPort != 8080 {
		t.Fatalf("containerPortが失われた: %+v", pod.Spec.Containers[0].Ports)
	}
	// Non-sensitive env values must survive: they are frequently the reason a
	// diagnosis fires, so masking them would make the replay useless.
	var logLevel string
	for _, env := range pod.Spec.Containers[0].Env {
		if env.Name == "LOG_LEVEL" {
			logLevel = env.Value
		}
	}
	if logLevel != "debug" {
		t.Fatalf("機密でない環境変数が失われた: %q", logLevel)
	}
	if len(loaded.Secrets) != 1 || loaded.Secrets[0].Name != "api-tls" || len(loaded.Secrets[0].Keys) != 2 {
		t.Fatalf("Secret射影が失われた: %+v", loaded.Secrets)
	}
	if !loaded.Available("pods") {
		t.Fatal("取得状況(pods=available)が失われた")
	}
	if status := loaded.Status("nodes"); status.Available || status.Reason != "forbidden" {
		t.Fatalf("取得失敗の理由が失われた: %+v", status)
	}
}

func TestClusterSnapshotMasksSecretsBeforeSharing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	scope := supportSnapshotScope()
	scope.Context = "token=scope-secret"
	if err := SaveClusterSnapshot(path, "v0.1.0", scope, supportSnapshot()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"annotation-secret", "env-secret", "warning-secret", "scope-secret"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("秘匿値 %q が共有用スナップショットに残った", secret)
		}
	}
	// encoding/json escapes < and > as < / >, so assert against the
	// decoded document rather than the raw bytes.
	var file ClusterSnapshotFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	masked := false
	for _, env := range file.Snapshot.Pods[0].Spec.Containers[0].Env {
		if env.Name == "DB_PASSWORD" && strings.HasPrefix(env.Value, "<masked-") && strings.HasSuffix(env.Value, ">") {
			masked = true
		}
	}
	if !masked {
		t.Errorf("機密環境変数がマスクされていない: %+v", file.Snapshot.Pods[0].Spec.Containers[0].Env)
	}
	// The file describes cluster internals even when masked.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("スナップショットの権限が0600でない: %o", perm)
		}
	}
}

func TestClusterSnapshotMaskingPreservesOnlySecretEquality(t *testing.T) {
	snapshot := NewSnapshot()
	snapshot.Pods = []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "api",
			Env: []corev1.EnvVar{
				{Name: "DB_PASSWORD", Value: "same-sensitive-value"},
				{Name: "API_TOKEN", Value: "same-sensitive-value"},
				{Name: "CLIENT_SECRET", Value: "different-sensitive-value"},
			},
		}}},
	}}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := SaveClusterSnapshot(path, "v0.1.0", supportSnapshotScope(), snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadClusterSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	values := loaded.Pods[0].Spec.Containers[0].Env
	if values[0].Value != values[1].Value {
		t.Fatalf("同じ秘匿値の同一性が失われた: %q != %q", values[0].Value, values[1].Value)
	}
	if values[0].Value == values[2].Value {
		t.Fatalf("異なる秘匿値が同じマーカーになり、再生時に差を判定できない: %q", values[0].Value)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range []string{"same-sensitive-value", "different-sensitive-value"} {
		if strings.Contains(string(data), original) {
			t.Fatalf("識別子を付けたマスクに元値が残った: %q", original)
		}
	}
}

func TestLoadClusterSnapshotRejectsForeignDocuments(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"not-json":       "{",
		"wrong-schema":   `{"schema":"k8s-diagnose/report/v1","snapshot":{}}`,
		"empty-snapshot": `{"schema":"` + ClusterSnapshotSchema + `"}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadClusterSnapshot(path); err == nil {
				t.Fatal("不正なスナップショットを受理した")
			}
		})
	}
}

// TestClusterSnapshotFileIsSelfDescribing keeps the envelope stable: a support
// file is useless if the receiver cannot tell which version produced it.
func TestClusterSnapshotFileIsSelfDescribing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := SaveClusterSnapshot(path, "v0.1.0", supportSnapshotScope(), supportSnapshot()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file ClusterSnapshotFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if file.Schema != ClusterSnapshotSchema {
		t.Errorf("schemaが不正: %q", file.Schema)
	}
	if file.Version != "v0.1.0" {
		t.Errorf("versionが記録されていない: %q", file.Version)
	}
	if file.SavedAt.IsZero() {
		t.Error("saved_atが記録されていない")
	}
	if file.Scope == nil || file.Scope.Context != "test-context" || file.Scope.Namespace != "prod" || file.Scope.Mode != "all" {
		t.Errorf("取得範囲が記録されていない: %#v", file.Scope)
	}
}

func TestClusterSnapshotReplayScopeMustMatchSavedScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := SaveClusterSnapshot(path, "v0.1.0", supportSnapshotScope(), supportSnapshot()); err != nil {
		t.Fatal(err)
	}
	file, err := LoadClusterSnapshotFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.ValidateReplayScope("prod", "all", false); err != nil {
		t.Fatalf("保存時と同じ範囲を拒否した: %v", err)
	}
	if err := file.ValidateReplayScope("", "all", false); err == nil || !strings.Contains(err.Error(), "namespace範囲") {
		t.Fatalf("namespace限定の入力を全namespaceとして再生できてしまう: %v", err)
	}
	if err := file.ValidateReplayScope("prod", "triage", false); err == nil || !strings.Contains(err.Error(), "診断モード") {
		t.Fatalf("別モードの不完全な入力を再生できてしまう: %v", err)
	}
	if err := file.ValidateReplayScope("prod", "all", true); err == nil || !strings.Contains(err.Error(), "未使用リソース") {
		t.Fatalf("--unused用データがない入力で未使用診断を実行できてしまう: %v", err)
	}
}

// TestScopedSnapshotDoesNotServeStaleIndex guards the lazy name index against
// the one pattern that can invalidate it: a shallow copy whose indexed
// collections are then replaced (how a diagnosis narrows to a selected Pod).
// Without ResetIndex the copy would keep answering from the original's
// contents and report objects the narrowed scope deliberately excluded.
func TestScopedSnapshotDoesNotServeStaleIndex(t *testing.T) {
	original := NewSnapshot()
	original.Secrets = []SecretProjection{
		{Namespace: "prod", Name: "keep"},
		{Namespace: "prod", Name: "drop"},
	}
	original.ConfigMaps = []corev1.ConfigMap{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "keep"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "drop"}},
	}
	// Prime the index on the original.
	if _, ok := original.Secret("prod", "drop"); !ok {
		t.Fatal("元のSnapshotでSecretを解決できない")
	}

	scoped := *original
	scoped.ResetIndex()
	scoped.Secrets = []SecretProjection{{Namespace: "prod", Name: "keep"}}
	scoped.ConfigMaps = []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "keep"}}}

	if _, ok := scoped.Secret("prod", "drop"); ok {
		t.Error("絞り込みで除外したSecretが解決された（インデックスが陳腐化）")
	}
	if _, ok := scoped.ConfigMap("prod", "drop"); ok {
		t.Error("絞り込みで除外したConfigMapが解決された（インデックスが陳腐化）")
	}
	if _, ok := scoped.Secret("prod", "keep"); !ok {
		t.Error("残すべきSecretを解決できない")
	}
	// The original must be unaffected.
	if _, ok := original.Secret("prod", "drop"); !ok {
		t.Error("元のSnapshotの解決結果が壊れた")
	}
}

func TestSnapshotIndexAccessors(t *testing.T) {
	snapshot := NewSnapshot()
	snapshot.PersistentVolumeClaims = []corev1.PersistentVolumeClaim{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "data"}},
	}
	snapshot.PersistentVolumes = []corev1.PersistentVolume{
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-1"}},
	}
	snapshot.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "api"}},
	}
	if _, ok := snapshot.PersistentVolumeClaim("prod", "data"); !ok {
		t.Error("PVCを解決できない")
	}
	if _, ok := snapshot.PersistentVolumeClaim("other", "data"); ok {
		t.Error("別namespaceのPVCを解決した")
	}
	if _, ok := snapshot.PersistentVolume("pv-1"); !ok {
		t.Error("PVを解決できない")
	}
	if _, ok := snapshot.ServiceAccount("prod", "api"); !ok {
		t.Error("ServiceAccountを解決できない")
	}
	if _, ok := snapshot.ServiceAccount("prod", "missing"); ok {
		t.Error("存在しないServiceAccountを解決した")
	}
}

// TestSaveClusterSnapshotWritesSafely covers the write path's three guarantees
// at once, because this file is written repeatedly (re-running
// --save-cluster-snapshot over the same path is normal) and is meant to be
// handed to someone else.
func TestSaveClusterSnapshotWritesSafely(t *testing.T) {
	t.Run("does not follow a symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windowsではシンボリックリンク作成に特権が必要")
		}
		dir := t.TempDir()
		victim := filepath.Join(dir, "victim.txt")
		if err := os.WriteFile(victim, []byte("original-content"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "snapshot.json")
		if err := os.Symlink(victim, link); err != nil {
			t.Skipf("シンボリックリンクを作成できない環境: %v", err)
		}
		if err := SaveClusterSnapshot(link, "v0.1.0", supportSnapshotScope(), supportSnapshot()); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(victim)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "original-content" {
			t.Fatalf("シンボリックリンクを追跡してリンク先を上書きした: %.40q", data)
		}
		if info, err := os.Lstat(link); err != nil {
			t.Fatal(err)
		} else if info.Mode()&os.ModeSymlink != 0 {
			t.Error("保存先がシンボリックリンクのまま残った")
		}
	})

	t.Run("tightens permissions on an existing file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windowsではファイルモードの意味が異なる")
		}
		path := filepath.Join(t.TempDir(), "snapshot.json")
		if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := SaveClusterSnapshot(path, "v0.1.0", supportSnapshotScope(), supportSnapshot()); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("上書き保存後の権限が0600でない: %o", perm)
		}
	})
}

// TestLoadClusterSnapshotRejectsOversizedFile keeps a corrupt or mistaken
// attachment from being read wholesale into memory. The function's whole
// purpose is reading a file someone else produced.
func TestLoadClusterSnapshotRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	// Sparse file: reports an oversized length without occupying the disk.
	if err := file.Truncate(maxClusterSnapshotBytes + 1); err != nil {
		file.Close()
		t.Skipf("スパースファイルを作成できない環境: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = LoadClusterSnapshot(path)
	if err == nil {
		t.Fatal("上限を超えるファイルを受理した")
	}
	if !strings.Contains(err.Error(), "大きすぎます") {
		t.Fatalf("サイズ超過だと分かるエラーになっていない: %v", err)
	}
}

// TestClusterSnapshotRoundTripMasksBinaryFields is the loud-failure guard for
// binaryValuedKeys: a []byte-valued field whose masked marker is not re-encoded
// makes the whole snapshot fail to load.
func TestClusterSnapshotRoundTripMasksBinaryFields(t *testing.T) {
	snapshot := NewSnapshot()
	snapshot.Secrets = []SecretProjection{{
		Namespace: "prod", Name: "api-tls",
		Keys:    map[string]struct{}{"tls.crt": {}},
		TLSCert: []byte("password=leaked-cert-material"),
	}}
	snapshot.ConfigMaps = []corev1.ConfigMap{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "assets"},
		BinaryData: map[string][]byte{"blob": []byte("token=leaked-blob-material")},
	}}
	snapshot.ValidatingWebhooks = []admissionv1.ValidatingWebhookConfiguration{{
		ObjectMeta: metav1.ObjectMeta{Name: "policy"},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name: "policy.example.com",
			ClientConfig: admissionv1.WebhookClientConfig{
				CABundle: []byte("password=leaked-ca-material"),
			},
		}},
	}}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := SaveClusterSnapshot(path, "v0.1.0", supportSnapshotScope(), snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadClusterSnapshot(path)
	if err != nil {
		t.Fatalf("バイナリ項目を含むスナップショットを読み込めない: %v", err)
	}
	if len(loaded.Secrets) != 1 || len(loaded.ConfigMaps) != 1 || len(loaded.ValidatingWebhooks) != 1 {
		t.Fatalf("構造が失われた: secrets=%d configmaps=%d webhooks=%d", len(loaded.Secrets), len(loaded.ConfigMaps), len(loaded.ValidatingWebhooks))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"leaked-cert-material", "leaked-blob-material", "leaked-ca-material"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("バイナリ項目の秘匿値が残った: %s", secret)
		}
	}
}

// TestSnapshotMaskingStaysReadable pins the human-facing side: a masked plain
// string must read as the marker, not as base64 that happens to decode to it.
func TestSnapshotMaskingStaysReadable(t *testing.T) {
	for _, value := range []string{"postgres", "pass", "hunter2!", "database"} {
		if got := maskLeafString(value, "<masked>", false); got != "<masked>" {
			t.Errorf("通常の文字列のマスクが読めない形式になった: %q -> %q", value, got)
		}
	}
	if got := maskLeafString("cert", "<masked>", true); got != base64.StdEncoding.EncodeToString([]byte("<masked>")) {
		t.Errorf("[]byte由来の値がbase64になっていない: %q", got)
	}
}
