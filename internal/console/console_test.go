package console

import (
	"bytes"
	"fmt"
	"strconv"
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
		{Check: model.Check{ID: "pod", Section: "Pod", Description: "Podとコンテナの稼働状態", Available: true}, InputSummaries: []string{"Pod一覧: 0件（この診断範囲には存在しません）"}},
	}

	c.DiagnosticContents(items)
	got := buffer.String()
	// This section says what was looked at. The findings themselves are printed
	// in full under the severity lists and every blocked check is listed again
	// under 確認できなかった項目, so only counts and names belong here.
	for _, want := range []string{
		"診断内容（実施状況）",
		"✔ 実施済み 3件",
		"? 確認不能 1件",
		"は正常という意味ではなく",
		"検査: Podとコンテナの稼働状態",
		"対象: Pod一覧: 0件",
		"（この診断範囲には存在しません）",
		"結果: ✔ 所見なし",
		"ServiceのPod選択条件・Endpoint",
		"・targetPort",
		"$ kubectl get services",
		"結果: ✘ 確定異常 1件",
		"追加情報としてEndpointSlice一覧を取得",
		"結果: ✔ 追加情報を取得済み",
		"? 確認不能 1件（詳細は「確認できなかった項目」）",
		"理由: アクセス権限がありません",
		"TLS",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("診断内容に%qがない: %q", want, got)
		}
	}
	if strings.Contains(got, "dXNlcjpwYXNz") {
		t.Fatalf("確認不能理由から資格情報が漏れた: %q", got)
	}
	// The severity lists below carry the finding bodies; repeating them here made
	// this one section more than half of the whole report.
	if strings.Contains(got, "targetPortを解決") {
		t.Fatalf("所見本文が重大度別一覧と重複している: %q", got)
	}
	if strings.Index(got, "  Pod\n") >= strings.Index(got, "  Service\n") {
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
	if !strings.Contains(got, "結果: ▲ 警告 1件") {
		t.Fatalf("コマンド非表示時に結果まで消えた: %q", got)
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

func summaryWithCoverage(t *testing.T, available, blocked int) string {
	t.Helper()
	state := model.NewState()
	for i := 0; i < available; i++ {
		state.AddCheck(model.Check{ID: "ok-" + strconv.Itoa(i), Available: true})
	}
	for i := 0; i < blocked; i++ {
		state.AddCheck(model.Check{ID: "ng-" + strconv.Itoa(i), Available: false, Reason: "forbidden"})
	}
	buffer := &bytes.Buffer{}
	cfg := config.Defaults()
	cfg.Mode = "all"
	New(cfg, buffer, buffer).Summary(state)
	return buffer.String()
}

// A blocked run confirms few issues and therefore scores high. The headline is
// the most prominent thing on screen, so it must not read as an all-clear for a
// diagnosis that never ran.
func TestScoreHeadlineDoesNotClaimAnAllClearWhenMostChecksWereBlocked(t *testing.T) {
	out := summaryWithCoverage(t, 2, 14)
	if !strings.Contains(out, "100/100") {
		t.Fatalf("前提が変わっている（確定Issueなしでは満点のはず）: %s", out)
	}
	if !strings.Contains(out, "良好（確認できた範囲）") {
		t.Errorf("評価が確認できた範囲のものだと示されていない: %s", out)
	}
	if !strings.Contains(out, "クラスタ全体が正常であることを示すものではありません") {
		t.Errorf("カバレッジ不足の注記がない: %s", out)
	}
}

func TestScoreHeadlineStaysPlainWhenEverythingWasChecked(t *testing.T) {
	out := summaryWithCoverage(t, 16, 0)
	if strings.Contains(out, "確認できた範囲") || strings.Contains(out, "示すものではありません") {
		t.Errorf("全項目を確認できた実行に不要な注記が出ている: %s", out)
	}
}

// This section grew to more than half of the whole report because it repeated
// what the severity lists and 確認できなかった項目 already say. It must stay a
// summary of what was looked at.
func TestDiagnosticContentsStaysASummaryInsteadOfRepeatingEverything(t *testing.T) {
	items := []DiagnosticItem{}
	for i := 0; i < 20; i++ {
		items = append(items, DiagnosticItem{
			Check: model.Check{ID: fmt.Sprintf("blocked-%d", i), Section: fmt.Sprintf("分類%02d", i),
				Description: "取得できなかった検査", Available: false, Reason: "アクセス権限がありません"},
		})
	}
	items = append(items, DiagnosticItem{
		Check:    model.Check{ID: "clean", Section: "Pod", Description: "所見のない検査", Available: true},
		Commands: []string{"kubectl get pods -A -o json"},
	})
	buffer := &bytes.Buffer{}
	New(config.Defaults(), buffer, buffer).DiagnosticContents(items)
	got := buffer.String()

	// One shared reason is printed once, not once per blocked rule.
	if count := strings.Count(got, "アクセス権限がありません"); count != 1 {
		t.Errorf("同じ理由を%d回繰り返している: %q", count, got)
	}
	// A check with nothing to act on does not need a command to act with.
	if strings.Contains(got, "kubectl get pods") {
		t.Errorf("所見のない検査にまで確認コマンドを出している: %q", got)
	}
	if !strings.Contains(got, "結果: ✔ 所見なし") {
		t.Errorf("実施した検査が一覧から消えた: %q", got)
	}
	if lines := strings.Count(got, "\n"); lines > 20 {
		t.Errorf("21件の検査で%d行を使っている（要約になっていない）: %q", lines, got)
	}
}
