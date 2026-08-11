// Package report serializes diagnostics, snapshots, diffs and graph formats.
package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/jsonutil"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	"github.com/kmizuki03/k8s-diagnose/internal/redact"
)

const Schema = "k8s-diagnose/report/v1"

type Document map[string]any

func Build(state *model.State, cfg config.Config, context string) Document {
	ok, unavailable, total := state.CoverageCounts()
	counts, active := map[string]int{}, map[string]int{}
	for _, severity := range model.SeverityOrder {
		counts[string(severity)] = len(state.BySeverity(severity, false))
		active[string(severity)] = len(state.BySeverity(severity, true))
	}
	findings := make([]any, 0, len(state.Findings))
	for _, finding := range state.Findings {
		// Persisted and machine-readable output is always masked. --no-mask is
		// intentionally limited to the interactive console.
		findings = append(findings, serializeFinding(finding))
	}
	roots := make([]any, 0, len(state.RootCauses))
	confirmed, probable, related := 0, 0, 0
	for _, root := range state.RootCauses {
		switch root.Classification {
		case "root_cause":
			confirmed++
		case "cause_candidate":
			probable++
		default:
			related++
		}
		roots = append(roots, serializeRootCause(root))
	}
	observations := map[string]any{}
	for category, values := range state.Observations {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		rows := []any{}
		for _, key := range keys {
			row := map[string]any{"id": key, "value": maskStructured(values[key])}
			if object, ok := values[key].(map[string]any); ok {
				row = map[string]any{"id": key}
				for field, value := range object {
					row[field] = maskStructured(value)
				}
			}
			rows = append(rows, row)
		}
		observations[category] = rows
	}
	summary := map[string]any{
		"health": state.Health(), "coverage": state.Coverage(),
		"checks":   map[string]any{"ok": ok, "unavailable": unavailable, "total": total},
		"findings": counts, "active_findings": active,
		"acknowledged_findings": acknowledgedCount(state.Findings),
		"root_causes":           map[string]any{"confirmed": confirmed, "probable": probable, "related": related, "total": len(state.RootCauses)},
	}
	if scopedScore := state.ScopedScoreValue(); scopedScore != nil {
		summary["scoped_score"] = scopedScore
	}
	return Document{
		"schema":       Schema,
		"generated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"tool":         map[string]any{"name": "k8s-diagnose", "version": config.Version, "runtime": "go"},
		"target":       map[string]any{"context": context, "namespace": nullable(cfg.Namespace), "scope": cfg.ScopeLabel(), "mode": cfg.Mode, "config_file": nullable(cfg.ConfigFile)},
		"summary":      summary,
		"policy":       map[string]any{"fail_on": cfg.FailOn, "max_issues": cfg.MaxIssues, "would_fail": state.ShouldFail(cfg.FailOn, cfg.MaxIssues)},
		"findings":     findings, "root_causes": roots, "observations": observations,
	}
}

func maskStructured(value any) any {
	switch typed := value.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return value
	case string:
		return console.MaskSecrets(typed, true)
	case []string:
		result := make([]string, len(typed))
		for index, item := range typed {
			result[index] = console.MaskSecrets(item, true)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = maskStructured(item)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if redact.IsSensitiveKey(key) {
				result[key] = "<masked>"
				continue
			}
			result[key] = maskStructured(item)
		}
		return result
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return value
		}
		var decoded any
		if err := json.Unmarshal(data, &decoded); err != nil {
			return value
		}
		return maskStructured(decoded)
	}
}

// Sanitize is the final persistence/egress boundary. It also handles data
// loaded from older snapshots that may have been created before masking was an
// invariant.
func Sanitize(value any) any { return maskStructured(value) }

func serializeFinding(finding model.Finding) map[string]any {
	evidence := serializeEvidence(finding.Evidence)
	var acknowledgement any
	if finding.Acknowledgement != nil {
		value := *finding.Acknowledgement
		value.Reason = console.MaskSecrets(value.Reason, true)
		acknowledgement = value
	}
	return map[string]any{
		"id": finding.ID, "rule_id": nullable(finding.RuleID), "code": finding.Code, "severity": finding.Severity,
		"section": finding.Section, "message": console.MaskSecrets(finding.Message, true),
		"resource": nullable(finding.Resource), "stable_key": nullable(finding.StableKey),
		"reason":     nullable(console.MaskSecrets(finding.Reason, true)),
		"confidence": finding.Confidence, "evidence": evidence,
		"acknowledged": finding.Acknowledged, "acknowledgement": acknowledgement,
	}
}

func serializeRootCause(root model.RootCause) map[string]any {
	evidence := serializeEvidence(root.Evidence)
	impacts := func(values []model.Impact) []any {
		result := make([]any, 0, len(values))
		for _, impact := range values {
			result = append(result, map[string]any{
				"resource": impact.Resource, "kind": impact.Kind,
				"message": console.MaskSecrets(impact.Message, true), "relation": nullable(impact.Relation),
				"depth": impact.Depth, "finding_ids": impact.FindingIDs,
				"path": impact.Path, "path_relations": impact.PathRelations,
			})
		}
		return result
	}
	masked := func(values []string) []string {
		result := make([]string, len(values))
		for i, value := range values {
			result[i] = console.MaskSecrets(value, true)
		}
		return result
	}
	return map[string]any{
		"id": root.ID, "confirmed": root.Confirmed, "classification": root.Classification,
		"label": root.Label, "confidence": root.Confidence,
		"cause": serializeFinding(root.Cause), "evidence": evidence,
		"direct_impacts": impacts(root.DirectImpacts), "propagated_impacts": impacts(root.PropagatedImpacts),
		"impact_summary": root.ImpactSummary, "remediations": masked(root.Remediations),
		"commands": masked(root.Commands), "related_finding_ids": root.RelatedFindingIDs,
		"health_penalty": root.HealthPenalty,
	}
}

func serializeEvidence(values []model.Evidence) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		text := value.Value
		if value.Key != "" {
			text = value.Key + "=" + text
		}
		result = append(result, console.MaskSecrets(text, true))
	}
	return result
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func acknowledgedCount(findings []model.Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.Acknowledged {
			count++
		}
	}
	return count
}

func Render(format string, document Document) ([]byte, error) {
	document = sanitizeDocument(document)
	switch format {
	case "json":
		return JSON(document)
	case "sarif":
		return SARIF(document)
	case "junit":
		return JUnit(document)
	case "mermaid":
		return Mermaid(document), nil
	case "dot":
		return DOT(document), nil
	default:
		return nil, fmt.Errorf("未対応の出力形式です: %s", format)
	}
}

func JSON(document Document) ([]byte, error) {
	data, err := json.MarshalIndent(sanitizeDocument(document), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("JSONを生成できません: %w", err)
	}
	return append(data, '\n'), nil
}

func sanitizeDocument(document Document) Document {
	sanitized, ok := Sanitize(map[string]any(document)).(map[string]any)
	if !ok {
		return document
	}
	return Document(sanitized)
}

func SARIF(document Document) ([]byte, error) {
	findings := findingObjects(document)
	roots := rootObjects(document)
	rootsByFinding := map[string][]string{}
	for _, root := range roots {
		rootID := jsonutil.StringField(root, "id")
		for _, findingID := range stringSlice(root["related_finding_ids"]) {
			rootsByFinding[findingID] = append(rootsByFinding[findingID], rootID)
		}
	}
	rules := map[string]any{}
	results := []any{}
	for _, finding := range findings {
		code := jsonutil.StringField(finding, "code")
		if code == "" {
			code = "K8S.UNKNOWN"
		}
		section := jsonutil.StringField(finding, "section")
		if section == "" {
			section = "Kubernetes diagnosis"
		}
		level := sarifLevel(jsonutil.StringField(finding, "severity"))
		if _, exists := rules[code]; !exists {
			rules[code] = map[string]any{
				"id": code, "name": strings.ReplaceAll(code, ".", "_"),
				"shortDescription":     map[string]any{"text": section},
				"defaultConfiguration": map[string]any{"level": level},
			}
		}
		result := map[string]any{
			"ruleId": code, "level": level,
			"message":             map[string]any{"text": jsonutil.StringField(finding, "message")},
			"partialFingerprints": map[string]any{"k8sDiagnoseFingerprint": finding["id"]},
			"properties": map[string]any{
				"severity": finding["severity"], "section": section,
				"confidence": finding["confidence"], "evidence": finding["evidence"],
				"rootCauseIds": rootsByFinding[jsonutil.StringField(finding, "id")],
				"acknowledged": finding["acknowledged"], "acknowledgement": finding["acknowledgement"],
			},
		}
		if resource := jsonutil.StringField(finding, "resource"); resource != "" {
			result["locations"] = []any{map[string]any{"logicalLocations": []any{map[string]any{"fullyQualifiedName": resource, "kind": "Kubernetes resource"}}}}
		}
		if acknowledged, _ := finding["acknowledged"].(bool); acknowledged {
			justification := acknowledgementReason(finding["acknowledgement"])
			result["suppressions"] = []any{map[string]any{"kind": "external", "justification": justification}}
		}
		results = append(results, result)
	}
	ruleList := []any{}
	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ruleList = append(ruleList, rules[key])
	}
	summary, _ := document["summary"].(map[string]any)
	runProperties := map[string]any{
		"health": summary["health"], "coverage": summary["coverage"],
		"target": document["target"], "rootCauses": document["root_causes"],
	}
	if difference, ok := document["diff"].(map[string]any); ok {
		runProperties["diff"] = difference["counts"]
	}
	if analysis, ok := document["history_analysis"].(map[string]any); ok {
		runProperties["historyAnalysis"] = analysis
	}
	documentSARIF := map[string]any{
		"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "k8s-diagnose", "version": documentToolVersion(document), "rules": ruleList}},
			"results": results, "properties": runProperties,
		}},
	}
	return JSON(documentSARIF)
}

func sarifLevel(severity string) string {
	switch severity {
	case "issue":
		return "error"
	case "warning":
		return "warning"
	default:
		return "note"
	}
}

func documentToolVersion(document Document) string {
	if tool, ok := document["tool"].(map[string]any); ok {
		if version := jsonutil.StringField(tool, "version"); version != "" {
			return version
		}
	}
	return config.Version
}

type testsuite struct {
	XMLName    xml.Name       `xml:"testsuite"`
	Name       string         `xml:"name,attr"`
	Tests      int            `xml:"tests,attr"`
	Failures   int            `xml:"failures,attr"`
	Errors     int            `xml:"errors,attr"`
	Skipped    int            `xml:"skipped,attr"`
	Properties testproperties `xml:"properties"`
	Cases      []testcase     `xml:"testcase"`
}

type testcase struct {
	Name       string          `xml:"name,attr"`
	Classname  string          `xml:"classname,attr"`
	Properties *testproperties `xml:"properties,omitempty"`
	Failure    *testdetail     `xml:"failure,omitempty"`
	Error      *testdetail     `xml:"error,omitempty"`
	Skipped    *testdetail     `xml:"skipped,omitempty"`
	SystemOut  string          `xml:"system-out"`
}

type testdetail struct {
	Type    string `xml:"type,attr,omitempty"`
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

type testproperties struct {
	Values []testproperty `xml:"property"`
}

type testproperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

func JUnit(document Document) ([]byte, error) {
	suite := testsuite{Name: "k8s-diagnose"}
	findings := findingObjects(document)
	roots := rootObjects(document)
	rootsByFinding := map[string][]string{}
	for _, root := range roots {
		for _, findingID := range stringSlice(root["related_finding_ids"]) {
			rootsByFinding[findingID] = append(rootsByFinding[findingID], jsonutil.StringField(root, "id"))
		}
	}
	summary, _ := document["summary"].(map[string]any)
	target, _ := document["target"].(map[string]any)
	suite.Properties.Values = []testproperty{
		{Name: "health", Value: fmt.Sprint(summary["health"])},
		{Name: "coverage", Value: fmt.Sprint(summary["coverage"])},
		{Name: "context", Value: fmt.Sprint(target["context"])},
		{Name: "namespace", Value: fmt.Sprint(target["scope"])},
		{Name: "root_causes", Value: strconv.Itoa(len(roots))},
	}
	if len(roots) > 0 {
		if data, err := json.Marshal(roots); err == nil {
			suite.Properties.Values = append(suite.Properties.Values, testproperty{Name: "root_causes_json", Value: string(data)})
		}
	}
	if analysis, ok := document["history_analysis"].(map[string]any); ok {
		if data, err := json.Marshal(analysis); err == nil {
			suite.Properties.Values = append(suite.Properties.Values, testproperty{Name: "history_analysis_json", Value: string(data)})
		}
	}
	for _, finding := range findings {
		severity := jsonutil.StringField(finding, "severity")
		code := jsonutil.StringField(finding, "code")
		if code == "" {
			code = "K8S.UNKNOWN"
		}
		resource := jsonutil.StringField(finding, "resource")
		if resource == "" {
			resource = "cluster"
		}
		message := jsonutil.StringField(finding, "message")
		detailText := message
		if evidence := stringSlice(finding["evidence"]); len(evidence) > 0 {
			detailText += "\nEvidence:\n- " + strings.Join(evidence, "\n- ")
		}
		item := testcase{Name: code + " " + resource, Classname: jsonutil.StringField(finding, "section"), SystemOut: detailText}
		if rootIDs := rootsByFinding[jsonutil.StringField(finding, "id")]; len(rootIDs) > 0 {
			item.Properties = &testproperties{Values: []testproperty{{Name: "root_cause_ids", Value: strings.Join(rootIDs, ",")}}}
		}
		detail := &testdetail{Type: code, Message: message, Text: detailText}
		acknowledged, _ := finding["acknowledged"].(bool)
		switch {
		case acknowledged:
			detail.Type = "acknowledged"
			detail.Message = acknowledgementReason(finding["acknowledgement"])
			item.Skipped = detail
			suite.Skipped++
		case severity == "issue":
			item.Failure = detail
			suite.Failures++
		case severity == "unavailable":
			item.Error = detail
			suite.Errors++
		default:
			detail.Type = severity
			item.Skipped = detail
			suite.Skipped++
		}
		suite.Cases = append(suite.Cases, item)
	}
	if len(findings) == 0 {
		suite.Cases = append(suite.Cases, testcase{Name: "cluster-diagnosis", Classname: "k8s-diagnose"})
	}
	suite.Tests = len(suite.Cases)
	data, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(data, '\n')...), nil
}

func acknowledgementReason(value any) string {
	switch acknowledgement := value.(type) {
	case map[string]any:
		if reason := jsonutil.StringField(acknowledgement, "reason"); reason != "" {
			return reason
		}
	case model.Acknowledgement:
		if acknowledgement.Reason != "" {
			return acknowledgement.Reason
		}
	case *model.Acknowledgement:
		if acknowledgement != nil && acknowledgement.Reason != "" {
			return acknowledgement.Reason
		}
	}
	return "承認済み"
}

func Mermaid(document Document) []byte {
	nodes, edges := reportGraph(document)
	var output strings.Builder
	output.WriteString("%% k8s-diagnose Root Cause dependency graph\nflowchart LR\n")
	if len(nodes) == 0 {
		output.WriteString("  %% 相関済みのRoot Causeはありません\n")
		return []byte(output.String())
	}
	keys := make([]string, 0, len(nodes))
	for key := range nodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&output, "  %s[\"%s\"]\n", nodeID(key), escapeMermaid(nodes[key].Label))
	}
	for _, edge := range edges {
		fmt.Fprintf(&output, "  %s -->|\"%s\"| %s\n", nodeID(edge.From), escapeMermaid(relationLabel(edge.Relation)), nodeID(edge.To))
	}
	output.WriteString("  classDef rootCause fill:#fee2e2,stroke:#dc2626,color:#7f1d1d,stroke-width:3px\n")
	output.WriteString("  classDef causeCandidate fill:#fef3c7,stroke:#d97706,color:#78350f,stroke-width:2px\n")
	output.WriteString("  classDef relatedCandidate fill:#f3f4f6,stroke:#6b7280,color:#111827,stroke-dasharray: 5 3\n")
	output.WriteString("  classDef impact fill:#eff6ff,stroke:#2563eb,color:#1e3a8a\n")
	for _, class := range []string{"rootCause", "causeCandidate", "relatedCandidate", "impact"} {
		ids := []string{}
		for _, key := range keys {
			if nodes[key].Class == class {
				ids = append(ids, nodeID(key))
			}
		}
		if len(ids) > 0 {
			fmt.Fprintf(&output, "  class %s %s\n", strings.Join(ids, ","), class)
		}
	}
	return []byte(output.String())
}

func DOT(document Document) []byte {
	nodes, edges := reportGraph(document)
	var output strings.Builder
	output.WriteString("digraph \"k8s-diagnose\" {\n  rankdir=LR;\n")
	output.WriteString("  graph [charset=\"UTF-8\", bgcolor=\"transparent\"];\n")
	output.WriteString("  node [shape=box, style=\"rounded,filled\", fontname=\"sans-serif\"];\n")
	output.WriteString("  edge [fontname=\"sans-serif\", color=\"#64748b\"];\n")
	keys := make([]string, 0, len(nodes))
	for key := range nodes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fill, border, font, width := graphStyle(nodes[key].Class)
		fmt.Fprintf(&output, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\", fontcolor=\"%s\", penwidth=%d];\n",
			nodeID(key), escapeDOT(nodes[key].Label), fill, border, font, width)
	}
	for _, edge := range edges {
		fmt.Fprintf(&output, "  \"%s\" -> \"%s\" [label=\"%s\"];\n", nodeID(edge.From), nodeID(edge.To), escapeDOT(relationLabel(edge.Relation)))
	}
	if len(nodes) == 0 {
		output.WriteString("  // 相関済みのRoot Causeはありません\n")
	}
	output.WriteString("}\n")
	return []byte(output.String())
}

type reportGraphNode struct {
	Label string
	Class string
}

type reportGraphEdge struct {
	From, To, Relation string
}

func reportGraph(document Document) (map[string]reportGraphNode, []reportGraphEdge) {
	nodes := map[string]reportGraphNode{}
	edgeMap := map[string]reportGraphEdge{}
	priority := map[string]int{"impact": 0, "relatedCandidate": 1, "causeCandidate": 2, "rootCause": 3}
	addNode := func(resource, label, class string) {
		if resource == "" {
			return
		}
		current, exists := nodes[resource]
		if !exists || priority[class] > priority[current.Class] || current.Class == "impact" && len(label) > len(current.Label) {
			nodes[resource] = reportGraphNode{Label: label, Class: class}
		}
	}
	for _, root := range rootObjects(document) {
		cause, _ := root["cause"].(map[string]any)
		causeResource := jsonutil.StringField(cause, "resource")
		if causeResource == "" {
			causeResource = "Finding/" + jsonutil.StringField(root, "id")
		}
		class := map[string]string{"root_cause": "rootCause", "cause_candidate": "causeCandidate"}[jsonutil.StringField(root, "classification")]
		if class == "" {
			class = "relatedCandidate"
		}
		label := jsonutil.StringField(root, "label") + ": " + causeResource
		if message := graphText(jsonutil.StringField(cause, "message"), 140); message != "" {
			label += "\n" + message
		}
		addNode(causeResource, label, class)
		for _, group := range []string{"direct_impacts", "propagated_impacts"} {
			for _, impact := range jsonutil.Objects(root[group]) {
				target := jsonutil.StringField(impact, "resource")
				path := stringSlice(impact["path"])
				if len(path) == 0 && target != "" {
					path = []string{target}
				}
				relations := stringSlice(impact["path_relations"])
				previous, start := causeResource, 0
				if len(path) > 0 && path[0] == causeResource {
					start = 1
				}
				for index := start; index < len(path); index++ {
					resource := path[index]
					impactLabel := resource
					if resource == target {
						if message := graphText(jsonutil.StringField(impact, "message"), 140); message != "" {
							impactLabel += "\n" + message
						}
					}
					addNode(resource, impactLabel, "impact")
					relationIndex := index
					if start == 1 {
						relationIndex--
					}
					relation := ""
					if relationIndex >= 0 && relationIndex < len(relations) {
						relation = relations[relationIndex]
					}
					if relation == "" && index == len(path)-1 {
						relation = jsonutil.StringField(impact, "relation")
					}
					if relation == "" {
						relation = "affects"
					}
					if previous != resource {
						edge := reportGraphEdge{From: previous, To: resource, Relation: relation}
						edgeMap[edge.From+"\x00"+edge.To+"\x00"+edge.Relation] = edge
					}
					previous = resource
				}
			}
		}
	}
	edgeKeys := make([]string, 0, len(edgeMap))
	for key := range edgeMap {
		edgeKeys = append(edgeKeys, key)
	}
	sort.Strings(edgeKeys)
	edges := make([]reportGraphEdge, 0, len(edgeKeys))
	for _, key := range edgeKeys {
		edges = append(edges, edgeMap[key])
	}
	return nodes, edges
}

func nodeID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "n" + hex.EncodeToString(digest[:])[:14]
}

func escapeMermaid(value string) string {
	value = html.EscapeString(value)
	value = strings.ReplaceAll(value, "|", "&#124;")
	value = strings.ReplaceAll(value, "\n", "<br/>")
	return value
}

func escapeDOT(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return value
}

func graphText(value string, limit int) string {
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:max(1, limit-1)]) + "…"
}

func graphStyle(class string) (string, string, string, int) {
	switch class {
	case "rootCause":
		return "#fee2e2", "#dc2626", "#7f1d1d", 3
	case "causeCandidate":
		return "#fef3c7", "#d97706", "#78350f", 2
	case "relatedCandidate":
		return "#f3f4f6", "#6b7280", "#111827", 1
	default:
		return "#eff6ff", "#2563eb", "#1e3a8a", 1
	}
}

func relationLabel(value string) string {
	labels := map[string]string{
		"required-by-pod": "必須参照", "optional-reference": "optional参照",
		"generic-ephemeral-volume": "一時PVC参照",
		"probe-controls":           "Probe制御", "service-account": "ServiceAccount使用",
		"priority-class": "PriorityClass使用", "runtime-class": "RuntimeClass使用",
		"scheduled-pod": "Node配置", "workload-member": "管理元",
		"owned-workload": "上位管理元", "volume-binding": "PVバインド", "endpoint-registration": "Endpoint登録",
		"service-endpoints": "Service所属", "service-selector": "selector一致",
		"ingress-backend": "Ingress backend", "ingress-tls": "Ingress TLS",
		"webhook-client": "Webhook参照", "affects": "影響",
	}
	if label := labels[value]; label != "" {
		return label
	}
	return value
}

func WriteAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".k8s-diagnose-*")
	if err != nil {
		return fmt.Errorf("一時ファイルを作成できません: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("一時ファイルへレポートを書き込めません: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("レポートの一時ファイルを同期できません: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("レポートの一時ファイルを閉じられません: %w", err)
	}
	// path is the explicit CLI/config output destination; CreateTemp in the
	// same directory plus Rename is the atomic-write boundary, not a sandbox.
	if err := os.Rename(temporary, path); err != nil { // #nosec G703 -- user-selected report destination is intentional.
		return fmt.Errorf("レポートを保存先へ反映できません: %w", err)
	}
	// fsync the parent so the rename itself survives a sudden power loss on
	// filesystems that require explicit directory durability.
	if runtime.GOOS != "windows" {
		parent, err := os.Open(directory) // #nosec G304 -- parent of the explicit output path is intentionally opened for fsync.
		if err != nil {
			return fmt.Errorf("保存先ディレクトリを開けません: %w", err)
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if syncErr != nil {
			return fmt.Errorf("保存先ディレクトリを同期できません: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("保存先ディレクトリを閉じられません: %w", closeErr)
		}
	}
	return nil
}

func Load(path string) (Document, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- --diff explicitly selects the snapshot to read.
	if err != nil {
		return nil, fmt.Errorf("スナップショットを読み込めません: %w", err)
	}
	return decodeDocument(bytes.NewReader(data))
}

func decodeDocument(reader io.Reader) (Document, error) {
	var document Document
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("スナップショットのJSONが不正です: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("スナップショットのJSONの末尾に余分な値があります")
		}
		return nil, fmt.Errorf("スナップショットのJSONの末尾が不正です: %w", err)
	}
	if document["schema"] != Schema {
		return nil, fmt.Errorf("スナップショットのスキーマには対応していません: %v", document["schema"])
	}
	return document, nil
}

func Compare(before, after Document) map[string]any {
	beforeMap, afterMap := findingMap(before), findingMap(after)
	common, beforeOnly, afterOnly := setParts(beforeMap, afterMap)
	unavailable := jsonutil.UnavailableSections(after)
	beforeCorrelation := correlationMap(valuesForIDs(beforeMap, beforeOnly), false)
	afterCorrelation := correlationMap(valuesForIDs(afterMap, afterOnly), false)
	changedBefore, changedAfter := map[string]bool{}, map[string]bool{}
	worsened, improved, changed, unknown := []any{}, []any{}, []any{}, []any{}
	changedCommon := 0
	for _, id := range common {
		if semanticJSONEqual(stableFinding(beforeMap[id]), stableFinding(afterMap[id])) {
			continue
		}
		changed = append(changed, map[string]any{"before": beforeMap[id], "after": afterMap[id]})
		changedCommon++
	}
	for _, key := range commonKeys(beforeCorrelation, afterCorrelation) {
		previous, current := beforeCorrelation[key], afterCorrelation[key]
		previousID, currentID := jsonutil.StringField(previous, "id"), jsonutil.StringField(current, "id")
		changedBefore[previousID], changedAfter[currentID] = true, true
		pair := map[string]any{"before": previous, "after": current}
		if jsonutil.StringField(previous, "severity") != "unavailable" && jsonutil.StringField(current, "severity") == "unavailable" {
			if entry := unknownEntry(previous, unavailable, current); entry != nil {
				unknown = append(unknown, entry)
				continue
			}
		}
		switch beforeWeight, afterWeight := severityWeight(jsonutil.StringField(previous, "severity")), severityWeight(jsonutil.StringField(current, "severity")); {
		case afterWeight > beforeWeight:
			worsened = append(worsened, pair)
		case afterWeight < beforeWeight:
			improved = append(improved, pair)
		default:
			changed = append(changed, pair)
		}
	}
	resolved := []any{}
	for _, id := range beforeOnly {
		if changedBefore[id] {
			continue
		}
		value := beforeMap[id]
		if entry := unknownEntry(value, unavailable, nil); entry != nil {
			unknown = append(unknown, entry)
			continue
		}
		resolved = append(resolved, value)
	}
	newValues := []any{}
	for _, id := range afterOnly {
		if !changedAfter[id] {
			newValues = append(newValues, afterMap[id])
		}
	}
	counts := map[string]any{
		"new": len(newValues), "resolved": len(resolved), "unknown": len(unknown),
		"reconfirmed": 0, "worsened": len(worsened), "improved": len(improved),
		"changed": len(changed), "unchanged": len(common) - changedCommon,
	}
	return map[string]any{
		"baseline_generated_at": before["generated_at"], "counts": counts,
		"new": newValues, "resolved": resolved, "unknown": unknown, "reconfirmed": []any{},
		"worsened": worsened, "improved": improved, "changed": changed,
		"unchanged": len(common) - changedCommon, "root_causes": compareRootCauses(before, after, unavailable),
	}
}

func DiffText(diff map[string]any) string {
	counts, _ := diff["counts"].(map[string]any)
	return fmt.Sprintf("診断結果の差分\n  新規 %v / 解消 %v / 確認不能 %v / 再確認 %v / 悪化 %v / 改善 %v / 内容変更 %v / 継続 %v",
		counts["new"], counts["resolved"], counts["unknown"], counts["reconfirmed"], counts["worsened"], counts["improved"], counts["changed"], counts["unchanged"])
}

// CompareHistory compares with the newest sample while bridging one or more
// unavailable (unknown) samples. abnormal -> unknown -> abnormal is a
// reconfirmation, not a new incident and therefore does not retrigger webhooks.
func CompareHistory(previous []Document, current Document) (map[string]any, error) {
	if len(previous) == 0 {
		return nil, errors.New("履歴差分には1件以上の比較基準が必要です")
	}
	result := Compare(previous[len(previous)-1], current)
	newValues := jsonutil.Objects(result["new"])
	remaining := []any{}
	for _, after := range newValues {
		if jsonutil.StringField(after, "severity") == "unavailable" {
			remaining = append(remaining, after)
			continue
		}
		before, unknownSamples, generatedAt := lastKnownFinding(previous, after)
		if before == nil {
			remaining = append(remaining, after)
			continue
		}
		pair := map[string]any{"before": before, "after": after, "unknown_samples": unknownSamples, "last_known_generated_at": generatedAt}
		switch beforeWeight, afterWeight := severityWeight(jsonutil.StringField(before, "severity")), severityWeight(jsonutil.StringField(after, "severity")); {
		case afterWeight > beforeWeight:
			result["worsened"] = appendAny(result["worsened"], pair)
		case afterWeight < beforeWeight:
			result["improved"] = appendAny(result["improved"], pair)
		case jsonutil.StringField(before, "id") == jsonutil.StringField(after, "id"):
			result["reconfirmed"] = appendAny(result["reconfirmed"], pair)
		default:
			result["changed"] = appendAny(result["changed"], pair)
		}
	}
	result["new"] = remaining
	counts, _ := result["counts"].(map[string]any)
	for _, key := range []string{"new", "worsened", "improved", "changed", "reconfirmed"} {
		counts[key] = len(jsonutil.Objects(result[key]))
	}
	rootDiff, _ := result["root_causes"].(map[string]any)
	rootNew := jsonutil.Objects(rootDiff["new"])
	remainingRoots := []any{}
	for _, root := range rootNew {
		before, unknownSamples, generatedAt := lastKnownRoot(previous, root)
		if before == nil {
			remainingRoots = append(remainingRoots, root)
			continue
		}
		pair := map[string]any{"before": before, "after": root, "unknown_samples": unknownSamples, "last_known_generated_at": generatedAt}
		if semanticJSONEqual(stableRoot(before), stableRoot(root)) {
			rootDiff["reconfirmed"] = appendAny(rootDiff["reconfirmed"], pair)
		} else {
			rootDiff["changed"] = appendAny(rootDiff["changed"], pair)
		}
	}
	rootDiff["new"] = remainingRoots
	rootCounts, _ := rootDiff["counts"].(map[string]any)
	for _, key := range []string{"new", "changed", "reconfirmed"} {
		rootCounts[key] = len(jsonutil.Objects(rootDiff[key]))
	}
	return result, nil
}

func findingObjects(document Document) []map[string]any {
	return jsonutil.Objects(document["findings"])
}
func rootObjects(document Document) []map[string]any {
	return jsonutil.Objects(document["root_causes"])
}

func findingMap(document Document) map[string]map[string]any {
	result := map[string]map[string]any{}
	for _, value := range findingObjects(document) {
		if id := jsonutil.StringField(value, "id"); id != "" {
			result[id] = value
		}
	}
	return result
}

func rootMap(document Document) map[string]map[string]any {
	result := map[string]map[string]any{}
	for _, value := range rootObjects(document) {
		if id := jsonutil.StringField(value, "id"); id != "" {
			result[id] = value
		}
	}
	return result
}

func setParts(before, after map[string]map[string]any) (common, beforeOnly, afterOnly []string) {
	for id := range before {
		if _, exists := after[id]; exists {
			common = append(common, id)
		} else {
			beforeOnly = append(beforeOnly, id)
		}
	}
	for id := range after {
		if _, exists := before[id]; !exists {
			afterOnly = append(afterOnly, id)
		}
	}
	sort.Strings(common)
	sort.Strings(beforeOnly)
	sort.Strings(afterOnly)
	return
}

func valuesForIDs(values map[string]map[string]any, ids []string) []map[string]any {
	result := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		result = append(result, values[id])
	}
	return result
}

func correlationMap(values []map[string]any, roots bool) map[string]map[string]any {
	grouped := map[string][]map[string]any{}
	for _, value := range values {
		finding := value
		if roots {
			finding, _ = value["cause"].(map[string]any)
		}
		code, resource := jsonutil.StringField(finding, "code"), jsonutil.StringField(finding, "resource")
		if code == "" || resource == "" {
			continue
		}
		key := code + "\x00" + resource
		grouped[key] = append(grouped[key], value)
	}
	result := map[string]map[string]any{}
	for key, group := range grouped {
		if len(group) == 1 {
			result[key] = group[0]
		}
	}
	return result
}

func commonKeys(before, after map[string]map[string]any) []string {
	result := []string{}
	for key := range before {
		if _, exists := after[key]; exists {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}

func findingCorrelationKey(finding map[string]any) string {
	code, resource := jsonutil.StringField(finding, "code"), jsonutil.StringField(finding, "resource")
	if code == "" || resource == "" {
		return ""
	}
	return code + "\x00" + resource
}

func unknownEntry(before map[string]any, unavailable map[string][]map[string]any, after map[string]any) map[string]any {
	if jsonutil.StringField(before, "severity") == "unavailable" {
		return nil
	}
	section := jsonutil.StringField(before, "section")
	blockers := jsonutil.MatchingUnavailable(before, unavailable[section])
	if section == "" || len(blockers) == 0 {
		return nil
	}
	values := make([]any, len(blockers))
	for index := range blockers {
		values[index] = blockers[index]
	}
	result := map[string]any{"before": before, "section": section, "unavailable": values}
	if after != nil {
		result["after"] = after
	}
	return result
}

func compareRootCauses(before, after Document, unavailable map[string][]map[string]any) map[string]any {
	beforeMap, afterMap := rootMap(before), rootMap(after)
	common, beforeOnly, afterOnly := setParts(beforeMap, afterMap)
	changed := []any{}
	changedCommon := map[string]bool{}
	for _, id := range common {
		if !semanticJSONEqual(stableRoot(beforeMap[id]), stableRoot(afterMap[id])) {
			changed = append(changed, map[string]any{"before": beforeMap[id], "after": afterMap[id]})
			changedCommon[id] = true
		}
	}
	beforeCorrelation := correlationMap(valuesForIDs(beforeMap, beforeOnly), true)
	afterCorrelation := correlationMap(valuesForIDs(afterMap, afterOnly), true)
	correlatedBefore, correlatedAfter := map[string]bool{}, map[string]bool{}
	for _, key := range commonKeys(beforeCorrelation, afterCorrelation) {
		left, right := beforeCorrelation[key], afterCorrelation[key]
		correlatedBefore[jsonutil.StringField(left, "id")] = true
		correlatedAfter[jsonutil.StringField(right, "id")] = true
		changed = append(changed, map[string]any{"before": left, "after": right})
	}
	unknown, resolved, newValues := []any{}, []any{}, []any{}
	for _, id := range beforeOnly {
		if correlatedBefore[id] {
			continue
		}
		cause, _ := beforeMap[id]["cause"].(map[string]any)
		if entry := unknownEntry(cause, unavailable, nil); entry != nil {
			unknown = append(unknown, map[string]any{"before": beforeMap[id], "section": entry["section"], "unavailable": entry["unavailable"]})
		} else {
			resolved = append(resolved, beforeMap[id])
		}
	}
	for _, id := range afterOnly {
		if !correlatedAfter[id] {
			newValues = append(newValues, afterMap[id])
		}
	}
	unchanged := len(common) - len(changedCommon)
	return map[string]any{
		"counts": map[string]any{"new": len(newValues), "resolved": len(resolved), "unknown": len(unknown), "reconfirmed": 0, "changed": len(changed), "unchanged": unchanged},
		"new":    newValues, "resolved": resolved, "unknown": unknown, "reconfirmed": []any{}, "changed": changed, "unchanged": unchanged,
	}
}

func stableFinding(value map[string]any) map[string]any {
	result := map[string]any{}
	for _, key := range []string{"id", "code", "severity", "section", "resource", "reason", "stable_key", "confidence", "acknowledged", "acknowledgement"} {
		result[key] = value[key]
	}
	return result
}

func stableRoot(value map[string]any) map[string]any {
	cause, _ := value["cause"].(map[string]any)
	result := map[string]any{"cause": stableFinding(cause)}
	for _, key := range []string{"id", "confirmed", "classification", "label", "confidence", "impact_summary", "remediations", "commands", "related_finding_ids", "health_penalty"} {
		result[key] = value[key]
	}
	stableImpacts := func(raw any) []any {
		impacts := jsonutil.Objects(raw)
		items := make([]any, 0, len(impacts))
		for _, impact := range impacts {
			item := map[string]any{}
			for _, key := range []string{"resource", "kind", "relation", "depth", "finding_ids", "path", "path_relations"} {
				item[key] = impact[key]
			}
			items = append(items, item)
		}
		return items
	}
	result["direct_impacts"] = stableImpacts(value["direct_impacts"])
	result["propagated_impacts"] = stableImpacts(value["propagated_impacts"])
	return result
}

func semanticJSONEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func lastKnownFinding(previous []Document, current map[string]any) (map[string]any, int, any) {
	key, section := findingCorrelationKey(current), jsonutil.StringField(current, "section")
	if key == "" || section == "" {
		return nil, 0, nil
	}
	unknownSamples := 0
	for index := len(previous) - 1; index >= 0; index-- {
		document := previous[index]
		correlated := correlationMap(findingObjects(document), false)[key]
		if correlated != nil && jsonutil.StringField(correlated, "severity") != "unavailable" {
			if unknownSamples > 0 {
				return correlated, unknownSamples, document["generated_at"]
			}
			return nil, 0, nil
		}
		if jsonutil.EvaluationUnavailable(document, current) {
			unknownSamples++
			continue
		}
		return nil, 0, nil
	}
	return nil, 0, nil
}

func lastKnownRoot(previous []Document, current map[string]any) (map[string]any, int, any) {
	cause, _ := current["cause"].(map[string]any)
	key, section := findingCorrelationKey(cause), jsonutil.StringField(cause, "section")
	if key == "" || section == "" {
		return nil, 0, nil
	}
	unknownSamples := 0
	for index := len(previous) - 1; index >= 0; index-- {
		document := previous[index]
		correlated := correlationMap(rootObjects(document), true)[key]
		if correlated != nil {
			if unknownSamples > 0 {
				return correlated, unknownSamples, document["generated_at"]
			}
			return nil, 0, nil
		}
		if jsonutil.EvaluationUnavailable(document, cause) {
			unknownSamples++
			continue
		}
		return nil, 0, nil
	}
	return nil, 0, nil
}

func appendAny(value any, items ...any) []any {
	result := []any{}
	if existing, ok := value.([]any); ok {
		result = append(result, existing...)
	}
	return append(result, items...)
}

func stringSlice(value any) []string {
	result := []string{}
	switch values := value.(type) {
	case []string:
		return values
	case []any:
		for _, item := range values {
			result = append(result, fmt.Sprint(item))
		}
	}
	return result
}

func severityWeight(value string) int {
	switch value {
	case "issue":
		return 4
	case "warning":
		return 3
	case "unavailable":
		return 2
	case "candidate":
		return 1
	default:
		return 0
	}
}
