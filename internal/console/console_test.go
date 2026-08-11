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

func TestDiagnosticContentsShowsEveryCheckAndUnavailableReason(t *testing.T) {
	buffer := &bytes.Buffer{}
	c := New(config.Defaults(), buffer, buffer)
	c.width = 56
	serviceFinding := model.NewFinding(model.Issue, "K8S.SERVICE.TEST", "Service", "Service/ns/api", "Invalid", "port", "Service ns/api のtargetPortを解決できません", 100)
	items := []DiagnosticItem{
		{Check: model.Check{ID: "tls", Section: "TLS", Description: "TLS Secret内のX.509証明書", Available: false, Reason: "アクセス権限がありません authorization=Basic dXNlcjpwYXNz"}},
		{Check: model.Check{ID: "service", Section: "Service", Description: "ServiceのPod選択条件・Endpoint・targetPort", Available: true}, Findings: []model.Finding{serviceFinding}, Commands: []string{"kubectl get services -A -o json"}},
		{Check: model.Check{ID: "service/optional/endpoint_slices", Section: "Service", Description: "追加情報としてEndpointSlice一覧を取得", Available: true}, Commands: []string{"kubectl get endpointslices.discovery.k8s.io -A -o json"}, Supplemental: true},
		{Check: model.Check{ID: "pod", Section: "Pod", Description: "Podとコンテナの稼働状態", Available: true}},
	}

	c.DiagnosticContents(items)
	got := buffer.String()
	for _, want := range []string{
		"診断内容（実施状況）",
		"✔ 実施済み 3件",
		"? 確認不能 1件",
		"各項目の確認コマンドを結果の前に表示します",
		"は正常という意味ではなく",
		"検査: Podとコンテナの稼働状態",
		"結果: ✔ 所見なし",
		"Podとコンテナの稼働状態",
		"ServiceのPod選択条件・Endpoint",
		"・targetPort",
		"$ kubectl get services",
		"結果: ✘ 確定異常 1件",
		"Service ns/api のtargetPortを解決",
		"できません",
		"追加情報としてEndpointSlice一覧を取得",
		"結果: ✔ 追加情報を取得済み",
		"TLS Secret内のX.509証明書",
		"結果: ? 確認不能",
		"理由: アクセス権限がありません",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("診断内容に%qがない: %q", want, got)
		}
	}
	if strings.Contains(got, "dXNlcjpwYXNz") {
		t.Fatalf("確認不能理由から資格情報が漏れた: %q", got)
	}
	if !(strings.Index(got, "  Pod\n") < strings.Index(got, "  Service\n") && strings.Index(got, "  Service\n") < strings.Index(got, "  TLS\n")) {
		t.Fatalf("診断分類が安定した順序で表示されていない: %q", got)
	}
	if items[0].Check.ID != "tls" || items[1].Check.ID != "service" || items[2].Check.ID != "service/optional/endpoint_slices" || items[3].Check.ID != "pod" {
		t.Fatalf("表示のために入力sliceを並べ替えた: %#v", items)
	}
}

func TestWrapDisplayKeepsAllWideTextWithinLimit(t *testing.T) {
	input := "NamespaceとPod名を対象にした診断内容"
	lines := wrapDisplay(input, 12)
	if strings.Join(lines, "") != input {
		t.Fatalf("折り返しで文字が欠落した: %#v", lines)
	}
	for _, line := range lines {
		if width := DisplayWidth(line); width > 12 {
			t.Fatalf("折り返し後の表示幅=%d, want <= 12: %q", width, line)
		}
	}
}

func TestDiagnosticContentsHonoursNoCmdAndStillShowsResult(t *testing.T) {
	buffer := &bytes.Buffer{}
	cfg := config.Defaults()
	cfg.ShowCmd = false
	c := New(cfg, buffer, buffer)
	c.DiagnosticContents([]DiagnosticItem{{
		Check:    model.Check{ID: "pod", Section: "Pod", Description: "Podの状態", Available: true},
		Commands: []string{"kubectl get pods -A -o json"},
		Findings: []model.Finding{model.NewFinding(model.Warning, "K8S.POD.TEST", "Pod", "Pod/ns/api", "NotReady", "ready", "PodがReadyではありません", 80)},
	}})
	got := buffer.String()
	if strings.Contains(got, "kubectl get pods") {
		t.Fatalf("コマンド非表示設定でも診断内容にkubectlが表示された: %q", got)
	}
	for _, want := range []string{"結果: ▲ 警告 1件", "[警告] PodがReadyではありません"} {
		if !strings.Contains(got, want) {
			t.Fatalf("コマンド非表示時に結果%qまで消えた: %q", want, got)
		}
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

func TestSummaryUsesPodScopeLabelInSelectMode(t *testing.T) {
	buffer := &bytes.Buffer{}
	cfg := config.Defaults()
	cfg.Mode = "select"
	c := New(cfg, buffer, buffer)
	state := model.NewState()
	state.AddCheck(model.Check{ID: "pod", Available: true})
	state.SetScopedScore(model.ScopedScore{
		Kind: "Pod", Resource: "Pod/ns/api", Score: 84, Maximum: 100,
		Dimensions: []model.ScoreDimension{
			{ID: "lifecycle", Label: "ライフサイクル", Score: 15, Maximum: 15, Detail: "phase=Running"},
			{ID: "readiness", Label: "Ready・Condition", Score: 15, Maximum: 15, Detail: "Ready=True"},
			{ID: "containers", Label: "コンテナ稼働", Score: 15, Maximum: 20, Detail: "Ready 1/1"},
			{ID: "restart-log", Label: "再起動・ログ", Score: 6, Maximum: 10, Detail: "再起動・OOM1"},
			{ID: "resources", Label: "Resources・構成", Score: 4, Maximum: 5, Detail: "候補1"},
			{ID: "scheduling", Label: "Scheduling・Node", Score: 8, Maximum: 8, Detail: "Node=node-a"},
			{ID: "dependencies", Label: "依存リソース", Score: 7, Maximum: 7, Detail: "異常所見なし"},
			{ID: "storage", Label: "Storage", Score: 4, Maximum: 4, Detail: "関連PVC 0"},
			{ID: "probe", Label: "Probe・接続", Score: 3, Maximum: 6, Detail: "警告1"},
			{ID: "service", Label: "Service・Endpoint", Score: 3, Maximum: 4, Detail: "候補1"},
			{ID: "network-policy", Label: "NetworkPolicy", Score: 2, Maximum: 2, Detail: "Policy 1"},
			{ID: "ingress-tls", Label: "Ingress・TLS", Score: 2, Maximum: 4, Detail: "警告1"},
		},
	})

	c.Summary(state)
	got := buffer.String()
	for _, want := range []string{
		"Pod総合スコア",
		"総合:",
		"84/100",
		"内訳:",
		"ライフサイクル",
		"Ready・Condition",
		"コンテナ稼働",
		"再起動・ログ",
		"Resources・構成",
		"Scheduling・Node",
		"依存リソース",
		"Storage",
		"Probe・接続",
		"Service・Endpoint",
		"NetworkPolicy",
		"Ingress・TLS",
		"総合＝選択Podの12診断項目（状態・依存・通信・TLS等）",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Pod個別診断のスコア表示に%qがない: %q", want, got)
		}
	}
	if strings.Contains(got, "クラスタ健全性スコア") || strings.Contains(got, "Health＝クラスタ状態") || strings.Contains(got, "Pod健全性スコア") {
		t.Fatalf("Pod個別診断にクラスタ全体の表記が残っています: %q", got)
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

func TestRootCauseEvidenceLabelsAreReadable(t *testing.T) {
	cases := []struct {
		evidence model.Evidence
		want     string
	}{
		{model.Evidence{Kind: "container", Key: "state"}, "コンテナの状態"},
		{model.Evidence{Kind: "pod", Key: "phase"}, "Podの状態（phase）"},
		{model.Evidence{Kind: "condition", Key: "Ready"}, "状態条件（condition） Ready"},
		{model.Evidence{Kind: "node", Key: "node-a"}, "Node node-a の配置不可理由"},
		{model.Evidence{Kind: "x509", Key: "notAfter"}, "証明書情報（notAfter）"},
	}
	for _, test := range cases {
		if got := rootCauseEvidenceLabel(test.evidence); got != test.want {
			t.Fatalf("根拠ラベル=%q, want %q", got, test.want)
		}
	}
}
