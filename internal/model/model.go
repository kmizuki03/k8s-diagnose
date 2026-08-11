// Package model defines structured findings, root causes and diagnostic state.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/kmizuki03/k8s-diagnose/internal/redact"
)

// Severity separates cluster failures from warnings, diagnostic gaps and hypotheses.
type Severity string

const (
	Issue       Severity = "issue"
	Warning     Severity = "warning"
	Unavailable Severity = "unavailable"
	Candidate   Severity = "candidate"
)

var SeverityOrder = []Severity{Issue, Warning, Unavailable, Candidate}

type Evidence struct {
	Kind  string `json:"kind,omitempty"`
	Key   string `json:"key,omitempty"`
	Value string `json:"value"`
}

type Acknowledgement struct {
	RuleID   string `json:"rule_id"`
	Reason   string `json:"reason"`
	Expires  string `json:"expires"`
	Source   string `json:"source,omitempty"`
	Workload string `json:"workload,omitempty"`
}

// Finding is intentionally independent from rendered text. ID is computed from
// stable semantic fields and never from Message, so changing counters or elapsed
// time does not turn one incident into a new incident.
type Finding struct {
	ID              string           `json:"id"`
	RuleID          string           `json:"rule_id,omitempty"`
	Code            string           `json:"code"`
	Severity        Severity         `json:"severity"`
	Section         string           `json:"section"`
	Message         string           `json:"message"`
	Resource        string           `json:"resource,omitempty"`
	Reason          string           `json:"reason,omitempty"`
	StableKey       string           `json:"stable_key,omitempty"`
	Confidence      int              `json:"confidence"`
	Evidence        []Evidence       `json:"evidence"`
	Acknowledged    bool             `json:"acknowledged"`
	Acknowledgement *Acknowledgement `json:"acknowledgement,omitempty"`
}

func NewFinding(severity Severity, code, section, resource, reason, stableKey, message string, confidence int, evidence ...Evidence) Finding {
	if confidence < 0 {
		confidence = defaultConfidence(severity)
	}
	if confidence > 100 {
		confidence = 100
	}
	if confidence < 0 {
		confidence = 0
	}
	f := Finding{
		Code: code, Severity: severity, Section: section, Resource: resource,
		Reason: redact.SanitizeText(reason), StableKey: stableKey, Message: redact.SanitizeText(message),
		Confidence: confidence, Evidence: compactEvidence(evidence),
	}
	f.ID = f.Fingerprint()
	return f
}

func defaultConfidence(severity Severity) int {
	switch severity {
	case Issue:
		return 95
	case Warning:
		return 70
	case Unavailable:
		return 100
	default:
		return 40
	}
}

func compactEvidence(values []Evidence) []Evidence {
	seen := map[string]struct{}{}
	result := make([]Evidence, 0, len(values))
	for _, value := range values {
		value.Value = strings.TrimSpace(redact.SanitizeText(value.Value))
		if value.Value == "" {
			continue
		}
		key := value.Kind + "\x00" + value.Key + "\x00" + value.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func (f Finding) Fingerprint() string {
	stable := f.StableKey
	if stable == "" {
		stable = f.Reason
	}
	payload := strings.Join([]string{f.Code, f.Resource, string(f.Severity), stable}, "\x00")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])[:20]
}

func (f Finding) CorrelationKey() string {
	return strings.Join([]string{f.Code, f.Resource, f.StableKey}, "\x00")
}

type Impact struct {
	Resource      string   `json:"resource"`
	Kind          string   `json:"kind"`
	Message       string   `json:"message"`
	Relation      string   `json:"relation,omitempty"`
	Depth         int      `json:"depth"`
	FindingIDs    []string `json:"finding_ids"`
	Path          []string `json:"path"`
	PathRelations []string `json:"path_relations"`
}

type RootCause struct {
	ID                string         `json:"id"`
	Confirmed         bool           `json:"confirmed"`
	Classification    string         `json:"classification"`
	Label             string         `json:"label"`
	Confidence        int            `json:"confidence"`
	Cause             Finding        `json:"cause"`
	Evidence          []Evidence     `json:"evidence"`
	DirectImpacts     []Impact       `json:"direct_impacts"`
	PropagatedImpacts []Impact       `json:"propagated_impacts"`
	ImpactSummary     map[string]int `json:"impact_summary"`
	Remediations      []string       `json:"remediations"`
	Commands          []string       `json:"commands"`
	RelatedFindingIDs []string       `json:"related_finding_ids"`
	HealthPenalty     int            `json:"health_penalty"`
}

func NewRootCause(cause Finding, confidence int, evidence []Evidence, direct, propagated []Impact, remediation, commands, related []string) RootCause {
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 100 {
		confidence = 100
	}
	classification, label := "related_candidate", "関連候補（要確認）"
	confirmed := cause.Severity == Issue && confidence >= 90
	if confirmed {
		classification, label = "root_cause", "根本原因"
	} else if confidence >= 60 {
		classification, label = "cause_candidate", "原因候補"
	}
	counts := map[string]int{}
	for _, impact := range append(append([]Impact{}, direct...), propagated...) {
		counts[impact.Kind]++
	}
	related = uniqueStrings(append([]string{cause.ID}, related...))
	penalty := 0
	if cause.Severity == Issue {
		unique := map[string]struct{}{}
		for _, impact := range append(append([]Impact{}, direct...), propagated...) {
			unique[impact.Resource] = struct{}{}
		}
		penalty = 8 + min(6, (len(unique)+1)/2)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{"root-cause", cause.Code, cause.Resource, cause.StableKey}, "\x00")))
	return RootCause{
		ID: hex.EncodeToString(sum[:])[:20], Confirmed: confirmed,
		Classification: classification, Label: label, Confidence: confidence,
		Cause: cause, Evidence: compactEvidence(evidence), DirectImpacts: direct,
		PropagatedImpacts: propagated, ImpactSummary: counts,
		Remediations: uniqueStrings(remediation), Commands: uniqueStrings(commands),
		RelatedFindingIDs: related, HealthPenalty: penalty,
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

type Check struct {
	ID          string `json:"id"`
	Section     string `json:"section"`
	Description string `json:"description"`
	Available   bool   `json:"available"`
	Reason      string `json:"reason,omitempty"`
}

// ScoreDimension is one independently explainable part of a scoped health
// score. Cluster diagnostics continue to use the root-cause based Health()
// calculation; interactive Pod diagnostics set a ScopedScore so a broken Pod
// is not presented as a nearly healthy cluster merely because it has one root
// cause.
type ScoreDimension struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Score   int    `json:"score"`
	Maximum int    `json:"maximum"`
	Detail  string `json:"detail,omitempty"`
}

type ScopedScore struct {
	Kind       string           `json:"kind"`
	Resource   string           `json:"resource"`
	Score      int              `json:"score"`
	Maximum    int              `json:"maximum"`
	Dimensions []ScoreDimension `json:"dimensions"`
}

type State struct {
	mu           sync.Mutex
	Findings     []Finding                 `json:"findings"`
	RootCauses   []RootCause               `json:"root_causes"`
	Checks       []Check                   `json:"checks"`
	Observations map[string]map[string]any `json:"observations"`
	ScopedScore  *ScopedScore              `json:"scoped_score,omitempty"`
	seen         map[string]struct{}
}

func NewState() *State {
	return &State{seen: map[string]struct{}{}, Observations: map[string]map[string]any{}}
}

func (s *State) Add(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := f.ID
	if key == "" {
		key = f.Fingerprint()
	}
	if _, ok := s.seen[key]; ok {
		return
	}
	s.seen[key] = struct{}{}
	s.Findings = append(s.Findings, f)
	s.RootCauses = nil
}

func (s *State) AddCheck(check Check) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := range s.Checks {
		if s.Checks[index].ID == check.ID {
			s.Checks[index] = check
			return
		}
	}
	s.Checks = append(s.Checks, check)
}

func (s *State) Observe(category, id string, value any) {
	if category == "" || id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Observations[category] == nil {
		s.Observations[category] = map[string]any{}
	}
	s.Observations[category][id] = value
}

func (s *State) BySeverity(severity Severity, activeOnly bool) []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []Finding{}
	for _, finding := range s.Findings {
		if finding.Severity == severity && (!activeOnly || !finding.Acknowledged) {
			result = append(result, finding)
		}
	}
	return result
}

func (s *State) SetRootCauses(values []RootCause) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RootCauses = values
}

func (s *State) SetScopedScore(value ScopedScore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := value
	copyValue.Score = max(0, min(copyValue.Maximum, copyValue.Score))
	copyValue.Dimensions = append([]ScoreDimension{}, value.Dimensions...)
	s.ScopedScore = &copyValue
}

func (s *State) ScopedScoreValue() *ScopedScore {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ScopedScore == nil {
		return nil
	}
	copyValue := *s.ScopedScore
	copyValue.Dimensions = append([]ScoreDimension{}, s.ScopedScore.Dimensions...)
	return &copyValue
}

// Acknowledge keeps findings visible while excluding them from CI policy.
// It returns true when the ID existed.
func (s *State) Acknowledge(id string, acknowledgement Acknowledgement) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := range s.Findings {
		if s.Findings[index].ID != id {
			continue
		}
		value := acknowledgement
		s.Findings[index].Acknowledged = true
		s.Findings[index].Acknowledgement = &value
		return true
	}
	return false
}

func (s *State) CoverageCounts() (ok, unavailable, total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, check := range s.Checks {
		if check.Available {
			ok++
		} else {
			unavailable++
		}
	}
	return ok, unavailable, len(s.Checks)
}

func (s *State) Coverage() int {
	ok, _, total := s.CoverageCounts()
	if total == 0 {
		return 100
	}
	return ok * 100 / total
}

func (s *State) Health() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ScopedScore != nil && s.ScopedScore.Maximum > 0 {
		return max(0, min(100, s.ScopedScore.Score*100/s.ScopedScore.Maximum))
	}
	if len(s.RootCauses) == 0 {
		issues := 0
		for _, finding := range s.Findings {
			if finding.Severity == Issue {
				issues++
			}
		}
		return max(0, 100-issues*8)
	}
	grouped := map[string]struct{}{}
	penalty := 0
	for _, root := range s.RootCauses {
		penalty += root.HealthPenalty
		if root.Cause.Severity == Issue {
			for _, id := range root.RelatedFindingIDs {
				grouped[id] = struct{}{}
			}
		}
	}
	for _, finding := range s.Findings {
		if finding.Severity != Issue {
			continue
		}
		if _, ok := grouped[finding.ID]; !ok {
			penalty += 8
		}
	}
	return max(0, 100-penalty)
}

func (s *State) ShouldFail(failOn string, maxIssues *int) bool {
	included := map[Severity]bool{}
	switch failOn {
	case "warning":
		included[Issue], included[Warning] = true, true
	case "unavailable":
		included[Issue], included[Warning], included[Unavailable] = true, true, true
	case "any":
		for _, severity := range SeverityOrder {
			included[severity] = true
		}
	case "none":
	default:
		included[Issue] = true
	}
	count := 0
	for _, finding := range s.Findings {
		if !finding.Acknowledged && included[finding.Severity] {
			count++
		}
	}
	if maxIssues != nil {
		return count > *maxIssues
	}
	return count > 0
}

func (s *State) Sort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	weight := map[Severity]int{Issue: 0, Warning: 1, Unavailable: 2, Candidate: 3}
	sort.SliceStable(s.Findings, func(i, j int) bool {
		a, b := s.Findings[i], s.Findings[j]
		if weight[a.Severity] != weight[b.Severity] {
			return weight[a.Severity] < weight[b.Severity]
		}
		if a.Section != b.Section {
			return a.Section < b.Section
		}
		return fmt.Sprintf("%s\x00%s", a.Resource, a.Code) < fmt.Sprintf("%s\x00%s", b.Resource, b.Code)
	})
}
