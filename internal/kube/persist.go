package kube

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/redact"
	"github.com/kmizuki03/k8s-diagnose/internal/report"
)

// ClusterSnapshotSchema versions the on-disk raw-input format. It is
// independent of the diagnosis report schema: this file stores the *input*
// (cluster state) rather than the *output* (findings), so a support case can be
// reproduced offline after the cluster has already been repaired.
const ClusterSnapshotSchema = "k8s-diagnose/cluster-snapshot/v2"

// maxClusterSnapshotBytes caps how large a received snapshot may be. A 12k-pod
// cluster serialises to roughly 100MB, so 512MB leaves generous headroom for
// the largest realistic input while still refusing a file that could only be
// corrupt, mistaken, or hostile.
const maxClusterSnapshotBytes int64 = 512 << 20

// ClusterSnapshotFile is the persisted envelope around a Snapshot.
type ClusterSnapshotFile struct {
	Schema   string                `json:"schema"`
	Version  string                `json:"version"`
	SavedAt  time.Time             `json:"saved_at"`
	Scope    *ClusterSnapshotScope `json:"scope"`
	Snapshot *Snapshot             `json:"snapshot"`
}

// ClusterSnapshotScope records how the input was collected. A namespaced or
// mode-limited snapshot is not interchangeable with a cluster-wide one: doing
// so would turn absent data into a false "resource does not exist" diagnosis.
// Context is descriptive only and deliberately is not required to match on
// replay, because the recipient need not have the original kubeconfig.
type ClusterSnapshotScope struct {
	Context   string `json:"context,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Mode      string `json:"mode"`
	Unused    bool   `json:"unused,omitempty"`
}

// ValidateReplayScope prevents a partial snapshot from being diagnosed under
// a broader or otherwise different scope than the one that produced it.
func (file *ClusterSnapshotFile) ValidateReplayScope(namespace, mode string, unused bool) error {
	if file == nil || file.Scope == nil {
		return errors.New("クラスタ状態に取得範囲の情報がありません。現在のバージョンで保存し直してください")
	}
	if file.Scope.Mode == "" {
		return errors.New("クラスタ状態に診断モードが記録されていません。現在のバージョンで保存し直してください")
	}
	if file.Scope.Namespace != namespace {
		return fmt.Errorf("クラスタ状態のnamespace範囲が一致しません（保存時: %s、再生時: %s）。保存時と同じ -n/--namespace を指定してください", scopeNamespace(file.Scope.Namespace), scopeNamespace(namespace))
	}
	if file.Scope.Mode != mode {
		return fmt.Errorf("クラスタ状態の診断モードが一致しません（保存時: %s、再生時: %s）。保存時と同じモードを指定してください", file.Scope.Mode, mode)
	}
	if file.Scope.Unused != unused {
		return fmt.Errorf("クラスタ状態の未使用リソース診断設定が一致しません（保存時: --unused=%t、再生時: --unused=%t）。保存時と同じ指定にしてください", file.Scope.Unused, unused)
	}
	return nil
}

func scopeNamespace(namespace string) string {
	if namespace == "" {
		return "全namespace"
	}
	return namespace
}

// SaveClusterSnapshot writes the collected cluster state to path with secrets
// masked, so a colleague can share a reproducible input without granting
// cluster access. The file is written 0600 because, even masked, it describes
// the internal topology of a cluster.
func SaveClusterSnapshot(path, version string, scope ClusterSnapshotScope, snapshot *Snapshot) error {
	if snapshot == nil {
		return fmt.Errorf("保存するクラスタ状態がありません")
	}
	if scope.Mode == "" {
		return fmt.Errorf("保存するクラスタ状態の診断モードがありません")
	}
	// Context names are normally harmless labels, but kubeconfig accepts an
	// arbitrary string. Apply the same masking and terminal sanitization as the
	// snapshot body so a context accidentally named "token=..." cannot escape
	// through envelope metadata.
	scope.Context = redact.MaskSecrets(scope.Context)
	masked, err := maskSnapshot(snapshot)
	if err != nil {
		return err
	}
	file := ClusterSnapshotFile{
		Schema:   ClusterSnapshotSchema,
		Version:  version,
		SavedAt:  time.Now().UTC(),
		Scope:    &scope,
		Snapshot: masked,
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("クラスタ状態をJSONへ変換できません: %w", err)
	}
	data = append(data, '\n')
	// report.WriteAtomic is the project's single safe-write primitive, and it is
	// what this file needs on every count. os.CreateTemp creates the temporary
	// at 0600, so the mode is a property of the new file rather than something
	// only applied when the destination did not already exist; os.Rename
	// replaces a symlink sitting at path instead of following it into someone
	// else's file; and the write is atomic, so an interrupted save cannot leave
	// a half-written snapshot that a colleague then tries to load.
	if err := report.WriteAtomic(path, data); err != nil {
		return fmt.Errorf("クラスタ状態を書き込めません: %w", err)
	}
	return nil
}

// LoadClusterSnapshotFile reads the complete envelope saved by
// SaveClusterSnapshot, including the collection scope needed for safe replay.
func LoadClusterSnapshotFile(path string) (*ClusterSnapshotFile, error) {
	// This function exists to read a file someone else produced and sent over,
	// so it must not assume the file is well-formed. A corrupted or mistaken
	// attachment would otherwise be read entirely into memory before any check
	// runs. Refuse anything implausible for a snapshot instead of failing with
	// an out-of-memory kill that tells the operator nothing.
	handle, err := os.Open(path) // #nosec G304 -- the operator explicitly names this snapshot file.
	if err != nil {
		return nil, fmt.Errorf("クラスタ状態を読み込めません: %w", err)
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil {
		return nil, fmt.Errorf("クラスタ状態を読み込めません: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("クラスタ状態のパスが通常ファイルではありません: %s", path)
	}
	if info.Size() > maxClusterSnapshotBytes {
		return nil, fmt.Errorf("クラスタ状態のファイルが大きすぎます: %dバイト（上限 %dバイト）。ファイルが破損しているか、別のファイルを指定していないか確認してください", info.Size(), maxClusterSnapshotBytes)
	}
	// Bound the read itself too: Stat and Read race on a file someone else can
	// still be writing, and a named pipe reports size 0 while yielding forever.
	data, err := io.ReadAll(io.LimitReader(handle, maxClusterSnapshotBytes+1))
	if err != nil {
		return nil, fmt.Errorf("クラスタ状態を読み込めません: %w", err)
	}
	if int64(len(data)) > maxClusterSnapshotBytes {
		return nil, fmt.Errorf("クラスタ状態のファイルが大きすぎます（上限 %dバイト）", maxClusterSnapshotBytes)
	}
	var file ClusterSnapshotFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("クラスタ状態のJSONを解析できません: %w", err)
	}
	if file.Schema != ClusterSnapshotSchema {
		return nil, fmt.Errorf("対応していないクラスタ状態スキーマです: %q（対応: %q）", file.Schema, ClusterSnapshotSchema)
	}
	if file.Scope == nil || file.Scope.Mode == "" {
		return nil, fmt.Errorf("クラスタ状態に取得範囲の情報がありません。現在のバージョンで保存し直してください: %s", path)
	}
	if file.Snapshot == nil {
		return nil, fmt.Errorf("クラスタ状態が空です: %s", path)
	}
	if file.Snapshot.Statuses == nil {
		file.Snapshot.Statuses = map[string]FetchStatus{}
	}
	return &file, nil
}

// LoadClusterSnapshot returns only the diagnostic input for callers that do
// not need the envelope metadata. Interactive replay uses
// LoadClusterSnapshotFile so it can validate the saved collection scope.
func LoadClusterSnapshot(path string) (*Snapshot, error) {
	file, err := LoadClusterSnapshotFile(path)
	if err != nil {
		return nil, err
	}
	return file.Snapshot, nil
}

// maskSnapshot round-trips the snapshot through JSON and masks every string
// value and sensitive key. Going through the generic representation means a
// newly added Snapshot field is masked automatically rather than silently
// leaking until someone remembers to update this function.
func maskSnapshot(snapshot *Snapshot) (*Snapshot, error) {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("クラスタ状態をJSONへ変換できません: %w", err)
	}
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("クラスタ状態を解析できません: %w", err)
	}
	comparisonKey := make([]byte, 32)
	if _, err := rand.Read(comparisonKey); err != nil {
		return nil, fmt.Errorf("マスク用の一時鍵を生成できません: %w", err)
	}
	maskedData, err := json.Marshal(maskStructuredValue(generic, false, comparisonKey))
	if err != nil {
		return nil, fmt.Errorf("マスク済みクラスタ状態をJSONへ変換できません: %w", err)
	}
	masked := NewSnapshot()
	if err := json.Unmarshal(maskedData, masked); err != nil {
		return nil, fmt.Errorf("マスク済みクラスタ状態を再構成できません: %w", err)
	}
	if masked.Statuses == nil {
		masked.Statuses = map[string]FetchStatus{}
	}
	return masked, nil
}

// binaryValuedKeys are the JSON keys whose values Go marshals from []byte, and
// therefore the only places a masked value must stay base64-decodable.
//
// Deciding this from the key is deliberate. The previous version sniffed the
// content instead, asking whether the original string happened to parse as
// base64 — which any 4/8/12-character string drawn from the base64 alphabet
// does. That turned ordinary values into unreadable markers ("postgres" became
// "PG1hc2tlZD4=") precisely in a file whose purpose is to be read by a human
// reviewing a colleague's cluster.
//
// Getting this list wrong fails loudly rather than silently: emitting the plain
// marker for a real []byte field makes the snapshot fail to load with "illegal
// base64 data", which TestClusterSnapshotRoundTripMasksBinaryFields covers.
var binaryValuedKeys = map[string]bool{
	"TLSCert":    true, // SecretProjection.TLSCert []byte (no json tag)
	"binaryData": true, // corev1.ConfigMap.BinaryData map[string][]byte
	"caBundle":   true, // admissionregistration webhook CABundle []byte
}

// maskStructuredValue walks the document. binary reports whether the current
// value came from a []byte-valued key, in which case a masked leaf is emitted
// as base64 so the field still decodes on load.
func maskStructuredValue(value any, binary bool, comparisonKey []byte) any {
	switch typed := value.(type) {
	case string:
		masked := redact.MaskSecrets(typed)
		return maskLeafString(typed, addComparisonFingerprint(typed, masked, comparisonKey), binary)
	case []any:
		result := make([]any, len(typed))
		for i, item := range typed {
			result[i] = maskStructuredValue(item, binary, comparisonKey)
		}
		return result
	case map[string]any:
		// Kubernetes encodes many settings as a {"name": ..., "value": ...}
		// pair (container env being the important one). There the credential
		// name lives in a sibling field rather than in the key, so a literal
		// DB_PASSWORD value would otherwise pass through untouched.
		nameValueSecret := false
		if name, ok := typed["name"].(string); ok && redact.IsSensitiveKey(name) {
			nameValueSecret = true
		}
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			// binaryData is a map of string to []byte, so its values inherit
			// the binary context rather than being binary themselves.
			childBinary := binary || binaryValuedKeys[key]
			// A sensitive key masks a scalar value outright. Containers are
			// still walked: Snapshot's own field names (notably "Secrets")
			// match the sensitive-key pattern, and collapsing those subtrees
			// would destroy the structure the replay depends on. Leaves
			// beneath are masked individually on the way down, and any deeper
			// sensitive key is re-checked at its own level.
			if redact.IsSensitiveKey(key) || nameValueSecret && key == "value" {
				if text, scalar := item.(string); scalar {
					masked := addComparisonFingerprint(text, "<masked>", comparisonKey)
					result[key] = maskLeafString(text, masked, childBinary)
					continue
				}
			}
			result[key] = maskStructuredValue(item, childBinary, comparisonKey)
		}
		return result
	default:
		return value
	}
}

var maskedMarkerRE = regexp.MustCompile(`<masked(?:-[a-z-]+)?>`)

// addComparisonFingerprint preserves only equality between masked values. The
// HMAC key is generated for one save operation and never written to disk, so a
// recipient cannot use the marker for an offline dictionary attack. This keeps
// replay accurate for rules such as "two secret-looking env values differ"
// without retaining either value.
func addComparisonFingerprint(original, masked string, comparisonKey []byte) string {
	if masked == original || len(comparisonKey) == 0 || !maskedMarkerRE.MatchString(masked) {
		return masked
	}
	digest := hmac.New(sha256.New, comparisonKey)
	_, _ = digest.Write([]byte(original))
	sum := digest.Sum(nil)
	// Encode six bytes as letters a-p. Keeping the marker alphabetic makes it
	// compatible with redact's existing idempotent <masked-...> recognition.
	code := make([]byte, 0, 12)
	for _, value := range sum[:6] {
		code = append(code, byte('a'+(value>>4)), byte('a'+(value&0x0f)))
	}
	return maskedMarkerRE.ReplaceAllStringFunc(masked, func(marker string) string {
		return strings.TrimSuffix(marker, ">") + "-" + string(code) + ">"
	})
}

// maskLeafString keeps a masked value loadable. Go marshals []byte fields as
// base64 strings, so substituting a plain marker there would make the snapshot
// fail to unmarshal with "illegal base64 data". Only values that actually came
// from such a field are re-encoded; everywhere else the marker stays readable.
func maskLeafString(original, masked string, binary bool) string {
	if masked == original {
		return original
	}
	if binary && original != "" {
		return base64.StdEncoding.EncodeToString([]byte(masked))
	}
	return masked
}
