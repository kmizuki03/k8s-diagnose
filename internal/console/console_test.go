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

func TestSelectedStyleIsAppliedAfterBothZebraColours(t *testing.T) {
	buffer := &bytes.Buffer{}
	c := &Console{
		Out:    buffer,
		Config: config.Defaults(),
		C:      Palette{Green: "GREEN", Lime: "LIME", Reverse: "REVERSE", Bold: "BOLD", Reset: "RESET"},
	}
	c.Table([]string{"ROW"}, []TableRow{
		{Cells: []string{"odd"}, Selected: true},
		{Cells: []string{"even"}, Selected: true},
	}, true)
	got := buffer.String()
	for _, want := range []string{"GREENREVERSEBOLDodd", "LIMEREVERSEBOLDeven"} {
		if !strings.Contains(got, want) {
			t.Fatalf("ゼブラ色の後に選択属性が適用されない: want=%q output=%q", want, got)
		}
	}
}

func TestTruncateDisplayHonoursWideCharacters(t *testing.T) {
	if got := TruncateDisplay("NamespaceとPod名を検索", 12); got != "Namespaceと…" || DisplayWidth(got) > 12 {
		t.Fatalf("表示幅で切り詰められない: %q width=%d", got, DisplayWidth(got))
	}
	if got := TruncateDisplay("接続確認", 5); got != "接続…" || DisplayWidth(got) > 5 {
		t.Fatalf("全角表示幅で切り詰められない: %q width=%d", got, DisplayWidth(got))
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

func TestSummaryRendersVisualHealthAndCoverageBars(t *testing.T) {
	buffer := &bytes.Buffer{}
	cfg := config.Defaults()
	console := New(cfg, buffer, buffer)
	state := model.NewState()
	state.Add(model.NewFinding(model.Issue, "K8S.TEST.ONE", "Pod", "Pod/ns/one", "Failed", "one", "one failed", 100))
	state.Add(model.NewFinding(model.Issue, "K8S.TEST.TWO", "Pod", "Pod/ns/two", "Failed", "two", "two failed", 100))
	state.AddCheck(model.Check{ID: "one", Available: true})
	state.AddCheck(model.Check{ID: "two", Available: true})
	state.AddCheck(model.Check{ID: "three", Available: false})

	console.Summary(state)
	got := buffer.String()
	for _, want := range []string{"Health:", "84/100", "[B] 注意", "Coverage:", "66%", "確認済み 2/3・確認不能 1項目", "所見:", "█", "░", "Health＝クラスタ状態"} {
		if !strings.Contains(got, want) {
			t.Fatalf("健全性表示に%qがない: %q", want, got)
		}
	}
}

func TestScoreBarUsesRequestedPercentage(t *testing.T) {
	if got := scoreBar(50, 10); got != "█████░░░░░" {
		t.Fatalf("50%%のゲージが不正: %q", got)
	}
	if got := scoreBar(100, 4); got != "████" {
		t.Fatalf("100%%のゲージが不正: %q", got)
	}
}

func TestRootCauseCommandsRespectNoCmd(t *testing.T) {
	buffer := &bytes.Buffer{}
	cfg := config.Defaults()
	cfg.ShowCmd = false
	console := New(cfg, buffer, buffer)
	finding := model.NewFinding(model.Issue, "K8S.TEST", "Pod", "Pod/ns/api", "Failed", "test", "Pod failed", 100)
	root := model.NewRootCause(finding, 100, nil, nil, nil, nil, []string{"kubectl get pod api -n ns"}, nil)
	console.RootCauseReport([]model.RootCause{root})
	if strings.Contains(buffer.String(), "kubectl get pod") {
		t.Fatalf("--no-cmd相当でもRoot Causeのコマンドが表示された: %q", buffer.String())
	}
}

func TestRootCauseExplainsDetectionRuleAndEvidence(t *testing.T) {
	buffer := &bytes.Buffer{}
	cfg := config.Defaults()
	console := New(cfg, buffer, buffer)
	finding := model.NewFinding(
		model.Issue, "K8S.SERVICE.TARGET_PORT_UNRESOLVED", "Service", "Service/ns/api", "TargetPortUnresolved", "web/admin",
		"Service ns/api のポートはtargetPort \"admin\"を指定していますが、対応するcontainerPort名がありません", 98,
		model.Evidence{Kind: "service", Key: "spec.ports", Value: "Serviceポート 80/TCP → targetPort \"admin\""},
		model.Evidence{Kind: "decision", Key: "unresolved", Value: "selectorに一致したPodを確認しましたが、targetPort \"admin\" と同名のTCP containerPortは見つかりませんでした（0件）"},
	)
	console.RootCauseReport([]model.RootCause{model.NewRootCause(finding, 98, finding.Evidence, nil, nil, nil, nil, nil)})
	got := buffer.String()
	for _, want := range []string{"[1] ✘ 根本原因\n", "検出理由: selectorに一致したPodを確認しましたが、targetPort \"admin\" と同名のTCP containerPortは見つかりませんでした（0件）", "検出理由・根拠", "判定ルール: K8S.SERVICE.TARGET_PORT_UNRESOLVED", "対象リソース: Service/ns/api", "Serviceポート設定: Serviceポート 80/TCP"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Root Causeの検出説明に%qがない: %q", want, got)
		}
	}
	if strings.Contains(got, "根本原因:") {
		t.Fatalf("概要に不自然なコロン連結が残っている: %q", got)
	}
}
