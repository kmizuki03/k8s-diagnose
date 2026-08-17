package history

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/report"
)

// TestHistoryDatabaseRejectsSymlinkTarget guards the shared-host (bastion)
// hardening: a symlink planted at the database path must be refused, and its
// target must never be chmod'd or written through.
func TestHistoryDatabaseRejectsSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.secret")
	if err := os.WriteFile(victim, []byte("do-not-touch"), 0o644); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "history.db")
	if err := os.Symlink(victim, dbPath); err != nil {
		t.Skipf("シンボリックリンクを作成できない環境のためスキップ: %v", err)
	}

	if err := ensurePrivateDatabaseFile(dbPath); err == nil {
		t.Fatal("シンボリックリンクを介した履歴DBを受理した")
	}
	if err := Validate(context.Background(), dbPath); err == nil {
		t.Fatal("Validateがシンボリックリンクの履歴DBを受理した")
	}

	info, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Fatalf("被害者ファイルの権限が変更された: %o", perm)
	}
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "do-not-touch" {
		t.Fatalf("被害者ファイルが書き換えられた: %q", data)
	}
}

func historyDocument(generated, severity string, restart int) report.Document {
	findings := []any{}
	if severity != "" {
		findings = append(findings, map[string]any{"id": "stable", "code": "K8S.TEST", "severity": severity, "section": "Pod", "resource": "Pod/ns/api", "message": "state", "acknowledged": false})
	}
	return report.Document{
		"schema": report.Schema, "generated_at": generated,
		"target":  map[string]any{"context": "test", "namespace": "ns", "mode": "triage"},
		"summary": map[string]any{"health": 100}, "findings": findings,
		"observations": map[string]any{"pod_restarts": []any{map[string]any{"id": "Pod/ns/api|app|api|uid", "resource": "Pod/ns/api", "container": "api", "pod_uid": "uid", "restart_count": restart}}},
	}
}

func TestSQLiteHistoryRoundTripAndSkipUnchanged(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "history.db")
	if err := Validate(ctx, path); err != nil {
		t.Fatal(err)
	}
	first := historyDocument("1", "issue", 1)
	inserted, err := Append(ctx, path, first, 10, false)
	if err != nil || !inserted {
		t.Fatalf("Append: inserted=%v err=%v", inserted, err)
	}
	unchanged := historyDocument("2", "issue", 1)
	inserted, err = Append(ctx, path, unchanged, 10, true)
	if err != nil || inserted {
		t.Fatalf("変化のないwatch履歴が保存された: inserted=%v err=%v", inserted, err)
	}
	values, err := Load(ctx, path, first, 10)
	if err != nil || len(values) != 1 {
		t.Fatalf("Load: len=%d err=%v", len(values), err)
	}
}

func TestWatchHistoryPersistsRootCausePathChanges(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "history.db")
	first := historyDocument("1", "issue", 1)
	root := func(route []any) []any {
		return []any{map[string]any{
			"id": "root", "confirmed": true, "classification": "root_cause", "confidence": 100, "health_penalty": 9,
			"cause":              map[string]any{"id": "stable", "severity": "issue", "confidence": 100, "acknowledged": false},
			"direct_impacts":     []any{map[string]any{"resource": "Pod/ns/api", "kind": "Pod", "relation": "required-by-pod", "depth": 1, "finding_ids": []any{"stable"}, "path": route, "path_relations": []any{"required-by-pod"}}},
			"propagated_impacts": []any{},
		}}
	}
	first["root_causes"] = root([]any{"Secret/ns/db", "Pod/ns/api"})
	if inserted, err := Append(ctx, path, first, 10, false); err != nil || !inserted {
		t.Fatalf("初回履歴を保存できない: inserted=%v err=%v", inserted, err)
	}
	second := historyDocument("2", "issue", 1)
	second["root_causes"] = root([]any{"Secret/ns/db", "ConfigMap/ns/mid", "Pod/ns/api"})
	if inserted, err := Append(ctx, path, second, 10, true); err != nil || !inserted {
		t.Fatalf("Root Cause経路変更を未変更として捨てた: inserted=%v err=%v", inserted, err)
	}
}

func TestSQLiteHistoryUsesPrivateModeAndLiteralQuestionMarkPath(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "history?private.db")
	document := historyDocument("1", "issue", 1)
	document["findings"].([]any)[0].(map[string]any)["message"] = `password="history-secret"`
	if inserted, err := Append(ctx, path, document, 10, false); err != nil || !inserted {
		t.Fatalf("特殊文字を含むDBへ保存できない: inserted=%v err=%v", inserted, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("履歴DB mode=%#o, want 0600", got)
	}
	loaded, err := Load(ctx, path, document, 1)
	if err != nil || len(loaded) != 1 {
		t.Fatalf("履歴を再読込できない: %#v %v", loaded, err)
	}
	payload := fmt.Sprint(loaded[0])
	if strings.Contains(payload, "history-secret") {
		t.Fatalf("履歴DBに未マスク値が保存された: %s", payload)
	}
	if _, err := os.Stat(strings.SplitN(path, "?", 2)[0]); err == nil {
		t.Fatal("?以降をDSNとして誤解釈した別ファイルが作られた")
	}
}

func TestLoadRejectsCorruptOrUnsupportedStoredDocuments(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
	}{
		{"trailing JSON", `{"schema":"k8s-diagnose/report/v1","findings":[]} {}`},
		{"unsupported schema", `{"schema":"k8s-diagnose/report/v0","findings":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "history.db")
			db, err := open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.ExecContext(ctx, `INSERT INTO diagnostic_runs(generated_at, context_name, namespace_name, mode_name, document_json) VALUES(?,?,?,?,?)`, "1", "test", "ns", "triage", test.payload)
			closeErr := db.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("破損fixtureを保存できない: insert=%v close=%v", err, closeErr)
			}
			if _, err := Load(ctx, path, historyDocument("2", "", 0), 1); err == nil {
				t.Fatalf("不正な履歴JSONを受理した: %s", test.payload)
			}
		})
	}
}

func TestAnalyzeFlappingAndRestartGrowth(t *testing.T) {
	values := []report.Document{
		historyDocument("1", "issue", 1),
		historyDocument("2", "", 2),
		historyDocument("3", "issue", 4),
	}
	current := historyDocument("4", "", 7)
	analysis := Analyze(values, current, 4, 3, 3)
	types := map[string]bool{}
	for _, trend := range analysis.Trends {
		types[trend.Type] = true
	}
	if !types["finding_flap"] || !types["restart_growth"] {
		t.Fatalf("履歴トレンドを検出できない: %#v", analysis.Trends)
	}
}

func TestAnalyzeDoesNotTreatAnotherRuleFailureAsUnknown(t *testing.T) {
	first := historyDocument("1", "issue", 1)
	firstFinding := first["findings"].([]any)[0].(map[string]any)
	firstFinding["rule_id"] = "pod-health"

	gap := historyDocument("2", "unavailable", 1)
	gapFinding := gap["findings"].([]any)[0].(map[string]any)
	gapFinding["id"] = "gap"
	gapFinding["code"] = "K8S.API.RULE_UNAVAILABLE"
	gapFinding["resource"] = "Rule/probe-config"
	gapFinding["rule_id"] = "probe-config"

	analysis := Analyze([]report.Document{first, gap}, historyDocument("3", "", 1), 3, 1, 100)
	if analysis.UnknownEvaluations != 0 {
		t.Fatalf("別ルールの取得不能をunknownへ数えた: %#v", analysis)
	}
	found := false
	for _, trend := range analysis.Trends {
		found = found || trend.Type == "finding_flap"
	}
	if !found {
		t.Fatalf("異常→正常の遷移を別ルールの取得不能で隠した: %#v", analysis.Trends)
	}
}
