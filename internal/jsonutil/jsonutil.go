// Package jsonutil contains the small, schema-compatible accessors shared by
// report diffing and history analysis.
package jsonutil

import (
	"fmt"
	"strings"
)

func Objects(value any) []map[string]any {
	result := []map[string]any{}
	switch values := value.(type) {
	case []any:
		for _, item := range values {
			if object, ok := item.(map[string]any); ok {
				result = append(result, object)
			}
		}
	case []map[string]any:
		return values
	}
	return result
}

func String(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func StringField(value map[string]any, key string) string {
	if value == nil {
		return ""
	}
	return String(value[key])
}

func Bool(value any) bool {
	result, _ := value.(bool)
	return result
}

func UnavailableSections(document map[string]any) map[string][]map[string]any {
	result := map[string][]map[string]any{}
	for _, finding := range Objects(document["findings"]) {
		if StringField(finding, "severity") != "unavailable" {
			continue
		}
		section := StringField(finding, "section")
		result[section] = append(result[section], finding)
	}
	return result
}

func MatchingUnavailable(finding map[string]any, blockers []map[string]any) []map[string]any {
	ruleID := StringField(finding, "rule_id")
	if ruleID == "" {
		return blockers // v1の旧snapshotは生成ルールを持たないためsection単位へフォールバックする
	}
	result := make([]map[string]any, 0, len(blockers))
	for _, blocker := range blockers {
		blockerRule := StringField(blocker, "rule_id")
		if blockerRule == "" {
			blockerRule = strings.TrimPrefix(StringField(blocker, "resource"), "Rule/")
		}
		if blockerRule == ruleID {
			result = append(result, blocker)
		}
	}
	return result
}

func EvaluationUnavailable(document map[string]any, finding map[string]any) bool {
	section := StringField(finding, "section")
	return section != "" && len(MatchingUnavailable(finding, UnavailableSections(document)[section])) > 0
}
