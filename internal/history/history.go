// Package history stores diagnosis reports and derives trends across runs.
//
// The SQLite schema is intentionally identical to the Python implementation so
// operators can switch runtimes without discarding their history database.
package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/jsonutil"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	"github.com/kmizuki03/k8s-diagnose/internal/report"
	_ "modernc.org/sqlite"
)

const (
	SchemaVersion  = 1
	AnalysisSchema = "k8s-diagnose/history-analysis/v1"
)

type Trend struct {
	Type        string   `json:"type"`
	Code        string   `json:"code"`
	Resource    string   `json:"resource"`
	Confidence  int      `json:"confidence"`
	Message     string   `json:"message"`
	Evidence    []string `json:"evidence"`
	Transitions int      `json:"transitions,omitempty"`
	States      []string `json:"states,omitempty"`
	Growth      int      `json:"growth,omitempty"`
}

type Analysis struct {
	Schema             string  `json:"schema"`
	Samples            int     `json:"samples"`
	Window             int     `json:"window"`
	FlapThreshold      int     `json:"flap_threshold"`
	RestartGrowth      int     `json:"restart_growth"`
	UnknownEvaluations int     `json:"unknown_evaluations"`
	Trends             []Trend `json:"trends"`
}

// Validate checks the destination and an existing database before any
// Kubernetes API request is made.
func Validate(ctx context.Context, path string) error {
	path, err := expandPath(path)
	if err != nil {
		return err
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("履歴DBを確認できません: %w", statErr)
		}
		parent, parentErr := os.Stat(filepath.Dir(path))
		if parentErr != nil || !parent.IsDir() {
			return fmt.Errorf("履歴DBの保存先ディレクトリがありません: %s", filepath.Dir(path))
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("履歴DBのパスがファイルではありません: %s", path)
	}
	db, err := open(ctx, path)
	if err != nil {
		return err
	}
	return db.Close()
}

func open(ctx context.Context, path string) (*sql.DB, error) {
	if err := ensurePrivateDatabaseFile(path); err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: path}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("履歴DBを開けません: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("履歴DBを初期化できません: %w", err)
	}
	if err := ensureSchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func ensurePrivateDatabaseFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- --history-db explicitly selects this private 0600 database.
	if err == nil {
		return file.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("履歴DBを安全に作成できません: %w", err)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return fmt.Errorf("履歴DBを確認できません: %w", statErr)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("履歴DBのパスがファイルではありません: %s", path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("履歴DBの権限を0600に設定できません: %w", err)
	}
	return nil
}

func ensureSchema(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("履歴DBのスキーマを確認できません: %w", err)
	}
	if version != 0 && version != SchemaVersion {
		return fmt.Errorf("履歴DBのスキーマバージョン %d には対応していません（対応バージョン: %d）", version, SchemaVersion)
	}
	var tableCount, diagnosisTable int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tableCount); err != nil {
		return fmt.Errorf("履歴DBのテーブルを確認できません: %w", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='diagnostic_runs'").Scan(&diagnosisTable); err != nil {
		return fmt.Errorf("履歴DBのテーブルを確認できません: %w", err)
	}
	if version == 0 && tableCount > 0 && diagnosisTable == 0 {
		return errors.New("指定されたSQLiteデータベースは、k8s-diagnoseの履歴DBではありません")
	}
	if version == SchemaVersion && diagnosisTable == 0 {
		return errors.New("履歴DBに diagnostic_runs テーブルがありません")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("履歴DBの初期化を開始できません: %w", err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE IF NOT EXISTS diagnostic_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at TEXT NOT NULL,
            context_name TEXT NOT NULL,
            namespace_name TEXT NOT NULL,
            mode_name TEXT NOT NULL,
            document_json TEXT NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS diagnostic_runs_target
         ON diagnostic_runs(context_name, namespace_name, mode_name, id DESC)`,
		fmt.Sprintf("PRAGMA user_version=%d", SchemaVersion),
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("履歴DBのスキーマを作成できません: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("履歴DBのスキーマを確定できません: %w", err)
	}
	return nil
}

func Load(ctx context.Context, path string, current report.Document, limit int) ([]report.Document, error) {
	if limit < 1 {
		return nil, nil
	}
	path, err := expandPath(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("履歴DBを確認できません: %w", err)
	}
	db, err := open(ctx, path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	contextName, namespace, mode := targetKey(current)
	rows, err := db.QueryContext(ctx, `SELECT document_json FROM diagnostic_runs
        WHERE context_name=? AND namespace_name=? AND mode_name=?
        ORDER BY id DESC LIMIT ?`, contextName, namespace, mode, limit)
	if err != nil {
		return nil, fmt.Errorf("履歴DBを読み込めません: %w", err)
	}
	defer rows.Close()
	documents := []report.Document{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("履歴DBを読み込めません: %w", err)
		}
		document, err := decodeDocument(payload)
		if err != nil {
			return nil, err
		}
		documents = append(documents, document)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("履歴DBを読み込めません: %w", err)
	}
	for left, right := 0, len(documents)-1; left < right; left, right = left+1, right-1 {
		documents[left], documents[right] = documents[right], documents[left]
	}
	return documents, nil
}

func Append(ctx context.Context, path string, document report.Document, retain int, skipUnchanged bool) (bool, error) {
	path, err := expandPath(path)
	if err != nil {
		return false, err
	}
	if sanitized, ok := report.Sanitize(map[string]any(document)).(map[string]any); ok {
		document = report.Document(sanitized)
	}
	db, err := open(ctx, path)
	if err != nil {
		return false, err
	}
	defer db.Close()
	contextName, namespace, mode := targetKey(document)
	payload, err := json.Marshal(document)
	if err != nil {
		return false, fmt.Errorf("履歴JSONを生成できません: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("履歴DBへの書き込みを開始できません: %w", err)
	}
	defer tx.Rollback()
	if skipUnchanged {
		var previousPayload string
		err := tx.QueryRowContext(ctx, `SELECT document_json FROM diagnostic_runs
            WHERE context_name=? AND namespace_name=? AND mode_name=?
            ORDER BY id DESC LIMIT 1`, contextName, namespace, mode).Scan(&previousPayload)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("履歴DBの直前のレコードを読み込めません: %w", err)
		}
		if err == nil {
			previous, decodeErr := decodeDocument(previousPayload)
			if decodeErr != nil {
				return false, decodeErr
			}
			if stateKey(previous) == stateKey(document) {
				return false, nil
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_runs(
        generated_at, context_name, namespace_name, mode_name, document_json
    ) VALUES(?,?,?,?,?)`, jsonutil.String(document["generated_at"]), contextName, namespace, mode, string(payload)); err != nil {
		return false, fmt.Errorf("履歴DBへ保存できません: %w", err)
	}
	if retain < 1 {
		retain = 1
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM diagnostic_runs WHERE id NOT IN (
        SELECT id FROM diagnostic_runs ORDER BY id DESC LIMIT ?
    )`, retain); err != nil {
		return false, fmt.Errorf("履歴DBの保持件数を整理できません: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("履歴DBへの保存を確定できません: %w", err)
	}
	return true, nil
}

func decodeDocument(payload string) (report.Document, error) {
	var document report.Document
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("履歴DB内の診断JSONが不正です: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("履歴DB内の診断JSONの末尾に余分な値があります")
		}
		return nil, fmt.Errorf("履歴DB内の診断JSONの末尾が不正です: %w", err)
	}
	if document["schema"] != report.Schema {
		return nil, fmt.Errorf("履歴DB内の診断スキーマには対応していません: %v", document["schema"])
	}
	if _, ok := document["findings"].([]any); !ok {
		return nil, errors.New("履歴DB内に不正な診断レコードがあります")
	}
	return document, nil
}

func Analyze(previous []report.Document, current report.Document, window, flapThreshold, restartGrowth int) Analysis {
	samples := append(append([]report.Document{}, previous...), current)
	if window < 2 {
		window = 2
	}
	if len(samples) > window {
		samples = samples[len(samples)-window:]
	}
	findingSamples := make([]map[string]map[string]any, len(samples))
	for index, document := range samples {
		findingSamples[index] = activeFindingMap(document)
	}
	analysis := Analysis{Schema: AnalysisSchema, Samples: len(samples), Window: window, FlapThreshold: flapThreshold, RestartGrowth: restartGrowth, Trends: []Trend{}}
	keys := map[string]struct{}{}
	for _, sample := range findingSamples {
		for key := range sample {
			keys[key] = struct{}{}
		}
	}
	for _, key := range sortedKeys(keys) {
		var latest map[string]any
		for index := len(findingSamples) - 1; index >= 0; index-- {
			if value := findingSamples[index][key]; value != nil {
				latest = value
				break
			}
		}
		if latest == nil {
			continue
		}
		states := make([]string, len(samples))
		for index := range samples {
			switch {
			case findingSamples[index][key] != nil:
				states[index] = "abnormal"
			case jsonutil.EvaluationUnavailable(samples[index], latest):
				states[index] = "unknown"
				analysis.UnknownEvaluations++
			default:
				states[index] = "normal"
			}
		}
		transitions := 0
		for index := 1; index < len(states); index++ {
			if states[index-1] != "unknown" && states[index] != "unknown" && states[index-1] != states[index] {
				transitions++
			}
		}
		if transitions < flapThreshold || !containsState(states, "abnormal") || !containsState(states, "normal") {
			continue
		}
		labels := make([]string, len(states))
		for index, state := range states {
			labels[index] = map[string]string{"abnormal": "異常", "normal": "正常", "unknown": "確認不能"}[state]
		}
		resource, code := jsonutil.String(latest["resource"]), jsonutil.String(latest["code"])
		analysis.Trends = append(analysis.Trends, Trend{
			Type: "finding_flap", Code: "K8S.HISTORY.FINDING_FLAP", Resource: resource,
			Confidence: 85, Transitions: transitions, States: states,
			Message:  fmt.Sprintf("リソース %s の所見 %s は、直近 %d回の診断で発生と解消を %d回繰り返しています", resource, code, len(samples), transitions),
			Evidence: []string{"states=" + strings.Join(labels, " → "), "sourceCode=" + code},
		})
	}

	restartSamples := make([]map[string]map[string]any, len(samples))
	restartKeys := map[string]struct{}{}
	for index, document := range samples {
		restartSamples[index] = restartMap(document)
		for key := range restartSamples[index] {
			restartKeys[key] = struct{}{}
		}
	}
	for _, key := range sortedKeys(restartKeys) {
		records := []map[string]any{}
		counts := []int{}
		for _, sample := range restartSamples {
			if value := sample[key]; value != nil {
				records = append(records, value)
				counts = append(counts, intValue(value["restart_count"]))
			}
		}
		if len(records) < 3 {
			continue
		}
		increases, decreasing := 0, false
		for index := 1; index < len(counts); index++ {
			if counts[index] > counts[index-1] {
				increases++
			}
			if counts[index] < counts[index-1] {
				decreasing = true
			}
		}
		growth := counts[len(counts)-1] - counts[0]
		if increases < 2 || decreasing || growth < restartGrowth {
			continue
		}
		latest := records[len(records)-1]
		resource, container := jsonutil.String(latest["resource"]), jsonutil.String(latest["container"])
		textCounts := make([]string, len(counts))
		for index, count := range counts {
			textCounts[index] = strconv.Itoa(count)
		}
		analysis.Trends = append(analysis.Trends, Trend{
			Type: "restart_growth", Code: "K8S.HISTORY.RESTART_GROWTH", Resource: resource,
			Confidence: 95, Growth: growth,
			Message:  fmt.Sprintf("リソース %s のコンテナ %s では、再起動回数が直近 %d回の診断で %d回から %d回へ増加しました", resource, container, len(counts), counts[0], counts[len(counts)-1]),
			Evidence: []string{"restartCounts=" + strings.Join(textCounts, "→"), "podUID=" + jsonutil.String(latest["pod_uid"])},
		})
	}
	sort.Slice(analysis.Trends, func(i, j int) bool {
		return analysis.Trends[i].Type+"\x00"+analysis.Trends[i].Resource < analysis.Trends[j].Type+"\x00"+analysis.Trends[j].Resource
	})
	return analysis
}

// AddFindings keeps historical trends as warnings, while preserving Root Cause
// groups already built from the current cluster state.
func AddFindings(state *model.State, analysis Analysis) {
	roots := append([]model.RootCause{}, state.RootCauses...)
	for _, trend := range analysis.Trends {
		evidence := make([]model.Evidence, 0, len(trend.Evidence))
		for _, value := range trend.Evidence {
			evidence = append(evidence, model.Evidence{Kind: "history", Value: value})
		}
		state.Add(model.NewFinding(model.Warning, trend.Code, "履歴トレンド", trend.Resource, trend.Type, trend.Type, trend.Message, trend.Confidence, evidence...))
	}
	state.SetRootCauses(roots)
}

func targetKey(document report.Document) (string, string, string) {
	target, _ := document["target"].(map[string]any)
	return jsonutil.String(target["context"]), jsonutil.String(target["namespace"]), jsonutil.String(target["mode"])
}

func stateKey(document report.Document) string {
	stable := map[string]any{"summary": document["summary"], "observations": document["observations"]}
	findings := []map[string]any{}
	for _, finding := range jsonutil.Objects(document["findings"]) {
		findings = append(findings, map[string]any{
			"id": finding["id"], "severity": finding["severity"], "confidence": finding["confidence"], "acknowledged": finding["acknowledged"],
		})
	}
	stable["findings"] = findings
	roots := []map[string]any{}
	for _, root := range jsonutil.Objects(document["root_causes"]) {
		cause, _ := root["cause"].(map[string]any)
		value := map[string]any{
			"id": root["id"], "confirmed": root["confirmed"], "classification": root["classification"],
			"confidence": root["confidence"], "health_penalty": root["health_penalty"], "impact_summary": root["impact_summary"],
			"remediations": root["remediations"], "commands": root["commands"], "related_finding_ids": root["related_finding_ids"],
			"cause": map[string]any{"id": cause["id"], "severity": cause["severity"], "confidence": cause["confidence"], "acknowledged": cause["acknowledged"]},
		}
		compactImpacts := func(raw any) []map[string]any {
			result := []map[string]any{}
			for _, impact := range jsonutil.Objects(raw) {
				result = append(result, map[string]any{
					"resource": impact["resource"], "kind": impact["kind"], "relation": impact["relation"], "depth": impact["depth"],
					"finding_ids": impact["finding_ids"], "path": impact["path"], "path_relations": impact["path_relations"],
				})
			}
			return result
		}
		value["direct_impacts"] = compactImpacts(root["direct_impacts"])
		value["propagated_impacts"] = compactImpacts(root["propagated_impacts"])
		roots = append(roots, value)
	}
	stable["root_causes"] = roots
	payload, _ := json.Marshal(stable)
	return string(payload)
}

func activeFindingMap(document report.Document) map[string]map[string]any {
	result := map[string]map[string]any{}
	for _, finding := range jsonutil.Objects(document["findings"]) {
		code, resource := jsonutil.String(finding["code"]), jsonutil.String(finding["resource"])
		if code == "" || resource == "" || strings.HasPrefix(code, "K8S.HISTORY.") || jsonutil.String(finding["severity"]) == "unavailable" || jsonutil.Bool(finding["acknowledged"]) {
			continue
		}
		result[code+"\x00"+resource] = finding
	}
	return result
}

func restartMap(document report.Document) map[string]map[string]any {
	observations, _ := document["observations"].(map[string]any)
	result := map[string]map[string]any{}
	for _, value := range jsonutil.Objects(observations["pod_restarts"]) {
		if id := jsonutil.String(value["id"]); id != "" {
			result[id] = value
		}
	}
	return result
}

func expandPath(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("履歴DBのパスに含まれる「~」を展開できません: %w", err)
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return filepath.Abs(path)
}

func intValue(value any) int {
	switch number := value.(type) {
	case int:
		return number
	case int32:
		return int(number)
	case int64:
		return int(number)
	case float64:
		return int(number)
	case json.Number:
		result, _ := number.Int64()
		return int(result)
	default:
		result, _ := strconv.Atoi(fmt.Sprint(number))
		return result
	}
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func containsState(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
