package model

import (
	"strings"
	"testing"
)

func TestFindingSanitizesUntrustedControlCharacters(t *testing.T) {
	finding := NewFinding(Warning, "K8S.TEST", "Test", "Pod/ns/app", "Reason\x1b", "stable", "bad\x1b[2Jmessage", 70,
		Evidence{Kind: "event", Value: "value\u202eoverride"})
	if strings.ContainsRune(finding.Message, '\x1b') || strings.ContainsRune(finding.Reason, '\x1b') || strings.ContainsRune(finding.Evidence[0].Value, '\u202e') {
		t.Fatalf("所見へ危険な制御文字が残った: %#v", finding)
	}
}

func TestFindingFingerprintIgnoresDynamicMessage(t *testing.T) {
	first := NewFinding(Warning, "K8S.POD.TERMINATING_STATE", "Pod", "Pod/ns/app", "Terminating", "terminating", "7分継続", 70)
	second := NewFinding(Warning, "K8S.POD.TERMINATING_STATE", "Pod", "Pod/ns/app", "Terminating", "terminating", "8分継続", 70)
	if first.ID != second.ID {
		t.Fatalf("可変メッセージでIDが変化した: %s != %s", first.ID, second.ID)
	}
	third := NewFinding(Warning, first.Code, first.Section, "Pod/ns/other", first.Reason, first.StableKey, first.Message, 70)
	if first.ID == third.ID {
		t.Fatal("異なるresourceが同一IDになった")
	}
}

func TestAcknowledgedFindingDoesNotFailPolicy(t *testing.T) {
	state := NewState()
	finding := NewFinding(Issue, "K8S.TEST", "Test", "Pod/ns/app", "Broken", "broken", "broken", 100)
	state.Add(finding)
	if !state.ShouldFail("issue", nil) {
		t.Fatal("未承認のissueで失敗しない")
	}
	if !state.Acknowledge(finding.ID, Acknowledgement{RuleID: "known", Reason: "accepted", Expires: "2099-01-01"}) {
		t.Fatal("所見を承認できない")
	}
	if state.ShouldFail("issue", nil) {
		t.Fatal("承認済みissueがCI失敗対象に残った")
	}
}

func TestRootCauseAvoidsDuplicateHealthPenalty(t *testing.T) {
	state := NewState()
	cause := NewFinding(Issue, "K8S.CAUSE", "Dependency", "Secret/ns/db", "MissingKey", "password", "missing", 100)
	symptom := NewFinding(Issue, "K8S.SYMPTOM", "Pod", "Pod/ns/api", "Broken", "broken", "broken", 100)
	state.Add(cause)
	state.Add(symptom)
	root := NewRootCause(cause, 100, nil, nil, nil, nil, nil, []string{cause.ID, symptom.ID})
	state.SetRootCauses([]RootCause{root})
	if got, want := state.Health(), 92; got != want {
		t.Fatalf("Health=%d, want %d", got, want)
	}
}

func TestScopedScoreOverridesClusterPenaltyHealth(t *testing.T) {
	state := NewState()
	state.Add(NewFinding(Issue, "K8S.POD.ABNORMAL_STATE", "Pod", "Pod/ns/api", "CrashLoopBackOff", "app", "broken", 100))
	state.SetScopedScore(ScopedScore{Kind: "Pod", Resource: "Pod/ns/api", Score: 58, Maximum: 100})
	if got := state.Health(); got != 58 {
		t.Fatalf("Pod総合スコアがHealthへ反映されない: %d", got)
	}
}

func TestStateDeduplicatesSameFindingIDEvenWhenMessageChanges(t *testing.T) {
	state := NewState()
	state.Add(NewFinding(Warning, "K8S.TEST", "Test", "Pod/ns/app", "State", "stable", "1分継続", 70))
	state.Add(NewFinding(Warning, "K8S.TEST", "Test", "Pod/ns/app", "State", "stable", "2分継続", 70))
	if len(state.Findings) != 1 {
		t.Fatalf("同じIDの所見が重複した: %#v", state.Findings)
	}
}
