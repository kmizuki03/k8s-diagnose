package console

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

func TestMaskSecretsCoversCommonCredentialShapes(t *testing.T) {
	input := strings.Join([]string{
		`password="two words"`,
		`Authorization: Basic dXNlcjpwYXNz`,
		`authorization=Basic dXNlcjpwYXNz`,
		`{"level":"error","password":"hunter2"}`,
		`{"token": "json-token"}`,
		`DB_PASSWORD=env-secret`,
		`aws_secret_access_key = aws-secret`,
		`postgres://user:pass@db/app`,
		`eyJhbGciOiJIUzI1NiJ9.abcdefghijk.abcdefghijklmnop`,
		`ghp_123456789012345678901234567890123456`,
		"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
	}, "\n")
	masked := MaskSecrets(input, true)
	for _, secret := range []string{"two words", "dXNlcjpwYXNz", "hunter2", "json-token", "env-secret", "aws-secret", "user:pass", "eyJhbGci", "ghp_", "abc"} {
		if strings.Contains(masked, secret) {
			t.Fatalf("秘密 %q が残った: %s", secret, masked)
		}
	}
}

func TestDisplayWidthTreatsJapaneseAsWide(t *testing.T) {
	if got := DisplayWidth("接続先"); got != 6 {
		t.Fatalf("DisplayWidth=%d, want 6", got)
	}
}

func TestFindingTableAndRootCauseApplyConfiguredMask(t *testing.T) {
	buffer := &bytes.Buffer{}
	cfg := config.Defaults()
	console := New(cfg, buffer, buffer)
	finding := model.NewFinding(model.Issue, "K8S.TEST", "Test", "Pod/ns/api", "Failure", "test", `authorization=Basic dXNlcjpwYXNz`, 100,
		model.Evidence{Kind: "event", Value: `password="evidence-secret"`})
	console.Flag(finding)
	console.Table([]string{"MESSAGE"}, []TableRow{{Cells: []string{`token=table-secret`}}}, false)
	console.RootCauseReport([]model.RootCause{model.NewRootCause(finding, 100, finding.Evidence, nil, nil, []string{`password=remediation-secret`}, nil, nil)})
	got := buffer.String()
	for _, secret := range []string{"dXNlcjpwYXNz", "evidence-secret", "table-secret", "remediation-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("既定maskから秘密 %q が漏れた: %s", secret, got)
		}
	}
}
