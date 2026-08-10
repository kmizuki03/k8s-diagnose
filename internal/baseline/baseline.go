// Package baseline loads and applies time-bounded acknowledged findings.
package baseline

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

type Rule struct {
	ID, Code, Namespace, Workload, Resource, Reason, Expires, Source string
}

type Baseline struct {
	Path  string
	Rules []Rule
}

var ruleID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$`)

func Load(path string) (Baseline, error) {
	if path == "" {
		return Baseline{}, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Baseline{}, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return Baseline{}, fmt.Errorf("ベースラインを読み込めません: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return Baseline{}, fmt.Errorf("ベースラインは1MiB以下の通常ファイルにしてください")
	}
	file, err := os.Open(absolute) // #nosec G304 -- --baseline explicitly selects a validated regular file.
	if err != nil {
		return Baseline{}, err
	}
	defer file.Close()
	values := map[string]map[string]string{}
	seenSections := map[string]string{}
	section := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		rawLine := scanner.Text()
		if !utf8.ValidString(rawLine) {
			return Baseline{}, fmt.Errorf("ベースラインがUTF-8ではありません (%d行目)", lineNumber)
		}
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if !strings.HasPrefix(strings.ToLower(section), "acknowledgement.") {
				return Baseline{}, fmt.Errorf("未知のセクションです: [%s]", section)
			}
			id := strings.TrimSpace(strings.SplitN(section, ".", 2)[1])
			if !ruleID.MatchString(id) {
				return Baseline{}, fmt.Errorf("承認IDが不正です: %q", id)
			}
			normalizedID := strings.ToLower(id)
			if _, exists := seenSections[normalizedID]; exists {
				return Baseline{}, fmt.Errorf("承認IDが重複しています: %s", id)
			}
			seenSections[normalizedID] = id
			section = id
			values[section] = map[string]string{}
			continue
		}
		if section == "" {
			return Baseline{}, fmt.Errorf("設定値は[acknowledgement.ID]内に記述してください (%d行目)", lineNumber)
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return Baseline{}, fmt.Errorf("形式が不正です (%d行目)", lineNumber)
		}
		key, value := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
		if !allowedKey(key) {
			return Baseline{}, fmt.Errorf("[%s]の未知のキーです: %s", section, key)
		}
		if _, exists := values[section][key]; exists {
			return Baseline{}, fmt.Errorf("[%s]のキーが重複しています: %s", section, key)
		}
		values[section][key] = value
	}
	if err := scanner.Err(); err != nil {
		return Baseline{}, err
	}
	rules := []Rule{}
	for id, value := range values {
		rule := Rule{ID: id, Code: value["code"], Namespace: value["namespace"], Workload: value["workload"], Resource: value["resource"], Reason: strings.Join(strings.Fields(value["reason"]), " "), Expires: value["expires"], Source: absolute}
		if rule.Code == "" || rule.Reason == "" || rule.Expires == "" {
			return Baseline{}, fmt.Errorf("[acknowledgement.%s]にはcode、reason、expiresが必要です", id)
		}
		if rule.Namespace == "" && rule.Workload == "" && rule.Resource == "" {
			return Baseline{}, fmt.Errorf("[acknowledgement.%s]はnamespace、workload、resourceのいずれかで範囲を限定してください", id)
		}
		if utf8.RuneCountInString(rule.Reason) > 500 {
			return Baseline{}, fmt.Errorf("[acknowledgement.%s] reasonは500文字以下です", id)
		}
		for _, matcher := range []struct{ label, value string }{
			{"code", rule.Code}, {"namespace", rule.Namespace}, {"workload", rule.Workload}, {"resource", rule.Resource},
		} {
			if strings.IndexFunc(matcher.value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
				return Baseline{}, fmt.Errorf("[acknowledgement.%s] %sに空白・制御文字は使用できません", id, matcher.label)
			}
		}
		if _, err := time.Parse("2006-01-02", rule.Expires); err != nil {
			return Baseline{}, fmt.Errorf("[acknowledgement.%s] expiresはYYYY-MM-DDで指定してください", id)
		}
		rules = append(rules, rule)
	}
	if len(rules) == 0 {
		return Baseline{}, fmt.Errorf("ベースラインに承認エントリがありません")
	}
	if len(rules) > 500 {
		return Baseline{}, fmt.Errorf("承認エントリは500件までです")
	}
	sort.Slice(rules, func(i, j int) bool {
		si := boolScore(rules[i].Namespace) + boolScore(rules[i].Workload) + boolScore(rules[i].Resource)
		sj := boolScore(rules[j].Namespace) + boolScore(rules[j].Workload) + boolScore(rules[j].Resource)
		if si != sj {
			return si > sj
		}
		return strings.ToLower(rules[i].ID) < strings.ToLower(rules[j].ID)
	})
	return Baseline{Path: absolute, Rules: rules}, nil
}

func allowedKey(value string) bool {
	switch value {
	case "code", "namespace", "workload", "resource", "expires", "reason":
		return true
	default:
		return false
	}
}

func boolScore(value string) int {
	if value == "" {
		return 0
	}
	return 1
}

type WorkloadResolver func(model.Finding) []string

func Apply(state *model.State, baseline Baseline, resolvers ...WorkloadResolver) int {
	if baseline.Path == "" {
		return 0
	}
	var resolveWorkloads WorkloadResolver
	if len(resolvers) > 0 {
		resolveWorkloads = resolvers[0]
	}
	today := time.Now().Format("2006-01-02")
	count := 0
	for _, rule := range baseline.Rules {
		if rule.Expires < today {
			state.Add(model.NewFinding(
				model.Warning, "K8S.BASELINE.EXPIRED", "ベースライン", "Baseline/"+rule.ID, "Expired", rule.ID,
				fmt.Sprintf("ベースライン承認 %s は%sに期限切れです", rule.ID, rule.Expires), 100,
				model.Evidence{Kind: "baseline", Key: "reason", Value: rule.Reason},
			))
			continue
		}
		for _, finding := range append([]model.Finding{}, state.Findings...) {
			if finding.Acknowledged || !match(rule.Code, finding.Code) || !matchResourceScope(rule, finding.Resource) {
				continue
			}
			workloadMatches, matchedWorkload := matchWorkload(rule, finding, state.RootCauses, resolveWorkloads)
			if !workloadMatches {
				continue
			}
			if state.Acknowledge(finding.ID, model.Acknowledgement{RuleID: rule.ID, Reason: rule.Reason, Expires: rule.Expires, Source: rule.Source, Workload: matchedWorkload}) {
				count++
			}
		}
	}
	// Acknowledging an upstream cause also acknowledges correlated symptoms.
	for _, root := range state.RootCauses {
		var acknowledgement *model.Acknowledgement
		for _, finding := range state.Findings {
			if finding.ID == root.Cause.ID {
				acknowledgement = finding.Acknowledgement
				break
			}
		}
		if acknowledgement == nil {
			continue
		}
		for _, id := range root.RelatedFindingIDs {
			if state.Acknowledge(id, *acknowledgement) {
				count++
			}
		}
	}
	return count
}

func matchResourceScope(rule Rule, resource string) bool {
	parts := strings.Split(resource, "/")
	namespace := ""
	if len(parts) >= 3 {
		namespace = parts[1]
	}
	if rule.Namespace != "" && !match(rule.Namespace, namespace) {
		return false
	}
	return rule.Resource == "" || match(rule.Resource, resource) || len(parts) >= 2 && match(rule.Resource, parts[0]+"/"+parts[len(parts)-1])
}

func matchWorkload(rule Rule, finding model.Finding, roots []model.RootCause, resolve WorkloadResolver) (bool, string) {
	if rule.Workload == "" {
		return true, ""
	}
	candidates := []string{}
	if resolve != nil {
		candidates = append(candidates, resolve(finding)...)
	}
	// Backward-compatible fallback for callers without a resource graph.
	// Prefer top-level controllers; ReplicaSet is only useful when no owning
	// Deployment (or another top-level workload) can be resolved.
	topLevel, replicaSets := []string{}, []string{}
	for _, root := range roots {
		if root.Cause.ID != finding.ID && !contains(root.RelatedFindingIDs, finding.ID) {
			continue
		}
		for _, impact := range append(append([]model.Impact{}, root.DirectImpacts...), root.PropagatedImpacts...) {
			switch {
			case isTopLevelWorkload(impact.Kind):
				topLevel = append(topLevel, impact.Resource)
			case impact.Kind == "ReplicaSet":
				replicaSets = append(replicaSets, impact.Resource)
			}
		}
	}
	if len(candidates) == 0 {
		if isTopLevelWorkload(resourceKind(finding.Resource)) {
			topLevel = append(topLevel, finding.Resource)
		} else if resourceKind(finding.Resource) == "ReplicaSet" {
			replicaSets = append(replicaSets, finding.Resource)
		}
		if len(topLevel) > 0 {
			candidates = topLevel
		} else {
			candidates = replicaSets
		}
	}
	candidates = uniqueStrings(candidates)
	if len(candidates) == 0 {
		return false, ""
	}
	for _, candidate := range candidates {
		parts := strings.Split(candidate, "/")
		short := candidate
		if len(parts) >= 2 {
			short = parts[0] + "/" + parts[len(parts)-1]
		}
		if !match(rule.Workload, candidate) && !match(rule.Workload, short) {
			return false, "" // shared dependency: all affected workloads must be acknowledged
		}
	}
	return true, strings.Join(candidates, ", ")
}

func match(pattern, value string) bool {
	var expression strings.Builder
	expression.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteString(".")
		default:
			expression.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	expression.WriteString("$")
	matched, _ := regexp.MatchString(expression.String(), value)
	return matched
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func resourceKind(resource string) string {
	if index := strings.Index(resource, "/"); index >= 0 {
		return resource[:index]
	}
	return resource
}

func isTopLevelWorkload(kind string) bool {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
		return true
	default:
		return false
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
