package report

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

func TestBuildAlwaysMasksPersistentOutputEvenWhenConsoleMaskIsDisabled(t *testing.T) {
	state := model.NewState()
	finding := model.NewFinding(model.Issue, "K8S.TEST.SECRET", "Test", "Pod/ns/api", "Secret", "secret", `request failed password="hunter2"`, 100,
		model.Evidence{Kind: "log", Key: "line", Value: `{"token":"json-token"}`})
	state.Add(finding)
	state.Observe("test", "nested", map[string]any{"value": "DB_PASSWORD=env-secret", "password": "bare-secret"})
	state.SetRootCauses([]model.RootCause{model.NewRootCause(finding, 100, finding.Evidence, nil, nil, []string{"client_secret=root-secret"}, nil, []string{finding.ID})})
	cfg := config.Defaults()
	cfg.Mask = false
	document := Build(state, cfg, "test")
	serializedFinding := document["findings"].([]any)[0].(map[string]any)
	if serializedFinding["reason"] != "Secret" {
		t.Fatalf("Finding.reasonが構造化出力から欠落: %#v", serializedFinding)
	}
	serializedRoot := document["root_causes"].([]any)[0].(map[string]any)
	rootEvidence := serializedRoot["evidence"].([]string)
	if len(rootEvidence) != 1 || !strings.HasPrefix(rootEvidence[0], "line=") {
		t.Fatalf("Root Cause evidenceのキーが欠落: %#v", rootEvidence)
	}
	document["diff"] = map[string]any{"resolved": []any{map[string]any{"message": "aws_secret_access_key=legacy-secret"}}}
	data, err := JSON(document)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range []string{"hunter2", "json-token", "env-secret", "bare-secret", "root-secret", "legacy-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("--no-mask相当でも永続出力へ秘密 %q が残った: %s", secret, text)
		}
	}
}

func finding(id, code, severity, section, resource, message string) map[string]any {
	return map[string]any{"id": id, "code": code, "severity": severity, "section": section, "resource": resource, "message": message, "confidence": 100, "evidence": []any{}, "acknowledged": false}
}

func TestSARIFPreservesFingerprintSuppressionAndRootCauseContext(t *testing.T) {
	acknowledged := finding("finding-1", "K8S.TEST", "issue", "Test", "Pod/ns/api", "broken")
	acknowledged["acknowledged"] = true
	acknowledged["acknowledgement"] = map[string]any{"reason": "maintenance"}
	doc := document("1", acknowledged)
	doc["summary"] = map[string]any{"health": 92, "coverage": 100}
	doc["root_causes"] = []any{map[string]any{
		"id": "root-1", "classification": "root_cause", "related_finding_ids": []any{"finding-1"},
		"cause": acknowledged,
	}}
	data, err := SARIF(doc)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	runs := value["runs"].([]any)
	run := runs[0].(map[string]any)
	result := run["results"].([]any)[0].(map[string]any)
	if result["level"] != "error" || result["partialFingerprints"] == nil || result["suppressions"] == nil || result["locations"] == nil {
		t.Fatalf("SARIFの診断情報が欠落: %#v", result)
	}
	properties := result["properties"].(map[string]any)
	if got := properties["rootCauseIds"].([]any); len(got) != 1 || got[0] != "root-1" {
		t.Fatalf("Root Cause参照が欠落: %#v", properties)
	}
}

func TestJUnitSeparatesUnavailableAcknowledgedAndHealthyRun(t *testing.T) {
	issue := finding("issue", "K8S.ISSUE", "issue", "Pod", "Pod/ns/api", "broken")
	issue["acknowledged"] = true
	issue["acknowledgement"] = map[string]any{"reason": "accepted"}
	unavailable := finding("gap", "K8S.API", "unavailable", "API", "Rule/pods", "forbidden")
	doc := document("1", issue, unavailable)
	doc["summary"] = map[string]any{"health": 92, "coverage": 50}
	doc["target"] = map[string]any{"context": "test", "scope": "ns"}
	data, err := JUnit(doc)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{`tests="2"`, `failures="0"`, `errors="1"`, `skipped="1"`, `<error`, `type="acknowledged"`, `<system-out>`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("JUnitに%qがない: %s", expected, text)
		}
	}
	healthy := document("2")
	healthy["summary"] = map[string]any{"health": 100, "coverage": 100}
	data, err = JUnit(healthy)
	if err != nil || !strings.Contains(string(data), `name="cluster-diagnosis"`) || !strings.Contains(string(data), `tests="1"`) {
		t.Fatalf("所見0件のJUnitが不正: %v %s", err, data)
	}
}

func TestGraphOutputsKeepRelationsAndStyles(t *testing.T) {
	cause := finding("cause", "K8S.DEPENDENCY.MISSING_KEY", "issue", "関連リソース", "Secret/ns/db", "password missing")
	doc := document("1", cause)
	doc["root_causes"] = []any{map[string]any{
		"id": "root", "label": "根本原因", "classification": "root_cause", "cause": cause,
		"direct_impacts": []any{map[string]any{
			"resource": "Pod/ns/api", "message": "起動不可", "relation": "required-by-pod",
			"path": []any{"Secret/ns/db", "Pod/ns/api"}, "path_relations": []any{"required-by-pod"},
		}},
		"propagated_impacts": []any{},
	}}
	mermaid := string(Mermaid(doc))
	dot := string(DOT(doc))
	if !strings.Contains(mermaid, "classDef rootCause") || !strings.Contains(mermaid, "必須参照") {
		t.Fatalf("Mermaidのstyle/relationが欠落: %s", mermaid)
	}
	if !strings.Contains(dot, `label="必須参照"`) || !strings.Contains(dot, `fillcolor="#fee2e2"`) {
		t.Fatalf("DOTのstyle/relationが欠落: %s", dot)
	}
}

func document(generated string, findings ...map[string]any) Document {
	values := make([]any, len(findings))
	for index := range findings {
		values[index] = findings[index]
	}
	return Document{"schema": Schema, "generated_at": generated, "findings": values, "root_causes": []any{}, "target": map[string]any{"context": "test", "namespace": "ns", "mode": "triage"}}
}

func count(diff map[string]any, key string) int {
	counts := diff["counts"].(map[string]any)
	return counts[key].(int)
}

func TestCompareUsesUnknownInsteadOfResolved(t *testing.T) {
	before := document("1", finding("old", "K8S.POD.ABNORMAL", "issue", "Pod", "Pod/ns/api", "broken"))
	after := document("2", finding("gap", "K8S.API.RULE_UNAVAILABLE", "unavailable", "Pod", "Rule/pods", "forbidden"))
	diff := Compare(before, after)
	if count(diff, "unknown") != 1 || count(diff, "resolved") != 0 {
		t.Fatalf("取得不能を解消と判定した: %#v", diff["counts"])
	}
}

func TestCompareAttributesUnavailableToTheProducingRule(t *testing.T) {
	previous := finding("old", "K8S.POD.ABNORMAL", "issue", "Pod", "Pod/ns/api", "broken")
	previous["rule_id"] = "pod-health"
	unrelated := finding("gap", "K8S.API.RULE_UNAVAILABLE", "unavailable", "Pod", "Rule/probe-config", "forbidden")
	unrelated["rule_id"] = "probe-config"
	diff := Compare(document("1", previous), document("2", unrelated))
	if count(diff, "unknown") != 0 || count(diff, "resolved") != 1 {
		t.Fatalf("別ルールの取得不能を既存Pod異常のunknownと誤判定した: %#v", diff["counts"])
	}

	related := finding("gap", "K8S.API.RULE_UNAVAILABLE", "unavailable", "Pod", "Rule/pod-health", "forbidden")
	related["rule_id"] = "pod-health"
	diff = Compare(document("1", previous), document("2", related))
	if count(diff, "unknown") != 1 || count(diff, "resolved") != 0 {
		t.Fatalf("同じルールの取得不能をunknownにできない: %#v", diff["counts"])
	}
}

func TestCompareDetectsConfidenceAndAcknowledgementChangesForStableID(t *testing.T) {
	previous := finding("stable", "K8S.POD.NOT_READY", "warning", "Pod", "Pod/ns/api", "Ready 0/1")
	previous["confidence"] = 70
	current := finding("stable", "K8S.POD.NOT_READY", "warning", "Pod", "Pod/ns/api", "Ready 0/1")
	current["confidence"] = 85
	current["acknowledged"] = true
	current["acknowledgement"] = map[string]any{"reason": "maintenance", "expires": "2030-01-01"}
	diff := Compare(document("1", previous), document("2", current))
	if count(diff, "changed") != 1 || count(diff, "unchanged") != 0 {
		t.Fatalf("同一IDの確信度/承認変更を継続扱いした: %#v", diff["counts"])
	}
}

func TestRootCauseDiffIgnoresDynamicMessageButDetectsPathChange(t *testing.T) {
	cause := finding("cause", "K8S.TEST", "issue", "Test", "Secret/ns/db", "old message")
	root := func(message string, path []any) map[string]any {
		return map[string]any{
			"id": "root", "confirmed": true, "classification": "root_cause", "label": "根本原因", "confidence": 100,
			"cause": cause, "evidence": []any{"dynamic evidence"}, "impact_summary": map[string]any{"Pod": 1},
			"direct_impacts":     []any{map[string]any{"resource": "Pod/ns/api", "kind": "Pod", "message": message, "relation": "required-by-pod", "depth": 1, "finding_ids": []any{"symptom"}, "path": path, "path_relations": []any{"required-by-pod"}}},
			"propagated_impacts": []any{}, "remediations": []any{"fix"}, "commands": []any{"check"}, "related_finding_ids": []any{"cause", "symptom"}, "health_penalty": 9,
		}
	}
	before := document("1", cause)
	after := document("2", cause)
	before["root_causes"] = []any{root("Ready 0/1 for 5m", []any{"Secret/ns/db", "Pod/ns/api"})}
	after["root_causes"] = []any{root("Ready 0/1 for 6m", []any{"Secret/ns/db", "Pod/ns/api"})}
	diff := Compare(before, after)
	rootDiff := diff["root_causes"].(map[string]any)
	if rootDiff["counts"].(map[string]any)["changed"] != 0 {
		t.Fatalf("動的messageだけでRoot Cause変更と判定した: %#v", rootDiff)
	}
	after["root_causes"] = []any{root("Ready 0/1 for 6m", []any{"Secret/ns/db", "ConfigMap/ns/mid", "Pod/ns/api"})}
	rootDiff = Compare(before, after)["root_causes"].(map[string]any)
	if rootDiff["counts"].(map[string]any)["changed"] != 1 {
		t.Fatalf("影響経路変更を見落とした: %#v", rootDiff)
	}
}

func TestCompareHistoryReconfirmsAfterUnknown(t *testing.T) {
	abnormal := finding("stable", "K8S.POD.ABNORMAL", "issue", "Pod", "Pod/ns/api", "broken")
	first := document("1", abnormal)
	unknown := document("2", finding("gap", "K8S.API.RULE_UNAVAILABLE", "unavailable", "Pod", "Rule/pods", "forbidden"))
	current := document("3", abnormal)
	diff, err := CompareHistory([]Document{first, unknown}, current)
	if err != nil {
		t.Fatal(err)
	}
	if count(diff, "new") != 0 || count(diff, "reconfirmed") != 1 {
		t.Fatalf("既存異常が再通知対象になる: %#v", diff["counts"])
	}
}

func TestReportFormatsAreMachineReadable(t *testing.T) {
	doc := document("1", finding("id", "K8S.TEST", "issue", "Test", "Pod/ns/api", "broken"))
	doc["summary"] = map[string]any{"health": 92, "coverage": 100}
	for _, format := range []string{"json", "sarif", "junit", "mermaid", "dot"} {
		t.Run(format, func(t *testing.T) {
			data, err := Render(format, doc)
			if err != nil || len(data) == 0 {
				t.Fatalf("Render(%s): %v", format, err)
			}
			switch format {
			case "json", "sarif":
				var value any
				if err := json.Unmarshal(data, &value); err != nil {
					t.Fatalf("不正なJSON: %v", err)
				}
			case "junit":
				var value any
				if err := xml.Unmarshal(data, &value); err != nil {
					t.Fatalf("不正なXML: %v", err)
				}
			}
		})
	}
}

func TestLoadRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	data := `{"schema":"` + Schema + `"} {"unexpected":true}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("末尾に余分なJSON値があるsnapshotを受理した")
	}
}
