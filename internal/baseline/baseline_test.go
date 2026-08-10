package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

func TestLoadRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.ini")
	data := "[acknowledgement.known]\ncode = K8S.POD.*\ncode = K8S.NODE.*\nnamespace = prod\nreason = approved\nexpires = 2099-01-01\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("重複キーを持つbaselineを受理した")
	}
}

func TestLoadRejectsCaseInsensitiveDuplicateIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.ini")
	data := "[acknowledgement.Known]\ncode = K8S.POD.*\nnamespace = prod\nreason = first\nexpires = 2099-01-01\n" +
		"[acknowledgement.known]\ncode = K8S.NODE.*\nnamespace = prod\nreason = second\nexpires = 2099-01-01\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("大文字小文字だけ異なる重複承認IDを受理した")
	}
}

func TestLoadRejectsWhitespaceControlAndInvalidUTF8InMatchers(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"matcher whitespace", []byte("[acknowledgement.known]\ncode = K8S.POD.* bad\nnamespace = prod\nreason = approved\nexpires = 2099-01-01\n")},
		{"matcher control", []byte("[acknowledgement.known]\ncode = K8S.POD.*\nnamespace = prod\nresource = Pod/prod/api\x7f\nreason = approved\nexpires = 2099-01-01\n")},
		{"invalid utf8", append([]byte("[acknowledgement.known]\ncode = K8S.POD.*\nnamespace = prod\nreason = "), 0xff)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "baseline.ini")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("曖昧または不正なbaselineを受理した")
			}
		})
	}
}

func TestReasonLimitCountsCharactersInsteadOfUTF8Bytes(t *testing.T) {
	for _, test := range []struct {
		name    string
		length  int
		wantErr bool
	}{
		{"500 Japanese characters", 500, false},
		{"501 Japanese characters", 501, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "baseline.ini")
			data := "[acknowledgement.known]\ncode = K8S.POD.*\nnamespace = prod\nreason = " + strings.Repeat("あ", test.length) + "\nexpires = 2099-01-01\n"
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if (err != nil) != test.wantErr {
				t.Fatalf("Load() error=%v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestApplyRequiresEverySharedWorkloadToMatch(t *testing.T) {
	newState := func() (*model.State, model.Finding) {
		state := model.NewState()
		finding := model.NewFinding(model.Issue, "K8S.DEPENDENCY.MISSING_KEY", "依存", "Secret/ns/shared", "MissingKey", "password", "missing", 100)
		state.Add(finding)
		return state, finding
	}
	resolve := WorkloadResolver(func(model.Finding) []string {
		return []string{"Deployment/ns/api", "Deployment/ns/worker"}
	})
	state, finding := newState()
	partial := Baseline{Path: "baseline.ini", Rules: []Rule{{
		ID: "partial", Code: finding.Code, Workload: "Deployment/api", Expires: "2099-01-01", Reason: "partial",
	}}}
	if count := Apply(state, partial, resolve); count != 0 || state.Findings[0].Acknowledged {
		t.Fatalf("共有依存先の一部だけを対象とする承認を適用した: count=%d finding=%#v", count, state.Findings[0])
	}

	state, finding = newState()
	complete := Baseline{Path: "baseline.ini", Rules: []Rule{{
		ID: "complete", Code: finding.Code, Workload: "Deployment/*", Expires: "2099-01-01", Reason: "complete",
	}}}
	if count := Apply(state, complete, resolve); count != 1 || !state.Findings[0].Acknowledged || state.Findings[0].Acknowledgement.Workload != "Deployment/ns/api, Deployment/ns/worker" {
		t.Fatalf("共有依存先の全consumerを対象とする承認を適用できない: count=%d finding=%#v", count, state.Findings[0])
	}
}
