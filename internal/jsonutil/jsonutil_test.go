package jsonutil

import "testing"

func TestEvaluationUnavailableMatchesProducingRule(t *testing.T) {
	document := map[string]any{"findings": []any{
		map[string]any{"severity": "unavailable", "section": "Pod", "rule_id": "pod"},
		map[string]any{"severity": "unavailable", "section": "Node", "rule_id": "node"},
	}}
	if !EvaluationUnavailable(document, map[string]any{"section": "Pod", "rule_id": "pod"}) {
		t.Fatal("同じ生成ルールの取得不能を対応付けられない")
	}
	if EvaluationUnavailable(document, map[string]any{"section": "Pod", "rule_id": "service"}) {
		t.Fatal("同じsection内の別ルールを取得不能と誤認した")
	}
}

func TestObjectsAndScalarAccessorsAcceptDecodedJSONShapes(t *testing.T) {
	object := map[string]any{"name": "api", "enabled": true}
	if values := Objects([]any{object, "ignored"}); len(values) != 1 || StringField(values[0], "name") != "api" || !Bool(values[0]["enabled"]) {
		t.Fatalf("JSON accessorが不正: %#v", values)
	}
}
