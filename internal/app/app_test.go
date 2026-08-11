package app

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/baseline"
	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	"github.com/kmizuki03/k8s-diagnose/internal/rules"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func TestRefreshPodTargetRejectsReplacement(t *testing.T) {
	current := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-2")}}
	runner := &Runner{Clients: &kube.Clients{Kube: kubefake.NewSimpleClientset(current)}}
	selected := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-1")}}
	if _, err := runner.refreshPodTarget(context.Background(), selected); err == nil {
		t.Fatal("同名で再作成されたPodへのdebugを許可した")
	}
}

func TestInterpretCanIResultTreatsAuthorizationDenialAsAValidAnswer(t *testing.T) {
	allowed, err := interpretCanIResult([]byte("no\n"), errors.New("exit status 1"))
	if err != nil || allowed {
		t.Fatalf("権限拒否をコマンド障害と誤認した: allowed=%v err=%v", allowed, err)
	}
	allowed, err = interpretCanIResult([]byte("yes\n"), nil)
	if err != nil || !allowed {
		t.Fatalf("許可応答を解釈できない: allowed=%v err=%v", allowed, err)
	}
	if _, err := interpretCanIResult([]byte("API unavailable"), errors.New("exit status 1")); err == nil {
		t.Fatal("実際のkubectl障害を権限拒否として握りつぶした")
	}
}

func TestLateHistoryOrConnectFindingReceivesBaselineAcknowledgement(t *testing.T) {
	state := model.NewState()
	finding := model.NewFinding(model.Warning, "K8S.HISTORY.RESTART_GROWTH", "履歴トレンド", "Pod/ns/api", "restart_growth", "restart_growth", "増加", 95)
	state.Add(finding)
	runner := &Runner{Baseline: baseline.Baseline{Path: "baseline.ini", Rules: []baseline.Rule{{
		ID: "known-restart", Code: finding.Code, Resource: finding.Resource,
		Expires: "2099-12-31", Reason: "既知の負荷試験",
	}}}}
	runner.applyBaselineToLateFindings(&kube.Snapshot{}, state)
	values := state.BySeverity(model.Warning, false)
	if len(values) != 1 || !values[0].Acknowledged {
		t.Fatalf("後段所見へbaselineが適用されない: %#v", values)
	}
}

func TestWorkloadBaselineUsesHealthyOwnerGraphForLatePodFinding(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-abc", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api-rs"}}}}
	replicaSet := appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api-rs", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "api"}}}}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, ReplicaSets: []appsv1.ReplicaSet{replicaSet}}
	state := model.NewState()
	finding := model.NewFinding(model.Warning, "K8S.CONNECT.HTTP_FAILED", "接続確認", "Pod/ns/api-abc", "HTTPFailed", "pod/readiness/8080", "HTTP 503", 65)
	state.Add(finding)
	runner := &Runner{Baseline: baseline.Baseline{Path: "baseline.ini", Rules: []baseline.Rule{{
		ID: "known-api", Code: finding.Code, Namespace: "ns", Workload: "Deployment/api",
		Expires: "2099-12-31", Reason: "既知の保守作業",
	}}}}
	runner.correlateAndApplyBaseline(snapshot, state)
	values := state.BySeverity(model.Warning, false)
	if len(values) != 1 || !values[0].Acknowledged || values[0].Acknowledgement == nil || values[0].Acknowledgement.Workload != "Deployment/ns/api" {
		t.Fatalf("健康なownerを使ってworkload baselineを適用できない: %#v", values)
	}
	if len(state.RootCauses) != 1 || state.RootCauses[0].Cause.Code != finding.Code || state.RootCauses[0].Classification != "cause_candidate" {
		t.Fatalf("単発接続失敗を低確信度の原因候補として相関できない: %#v", state.RootCauses)
	}
}

func TestErrorOutputMasksSecretsAndTerminalControls(t *testing.T) {
	buffer := &bytes.Buffer{}
	printError(buffer, fmt.Errorf("authorization=Basic dXNlcjpwYXNz\x1b[31m"))
	got := buffer.String()
	if strings.Contains(got, "dXNlcjpwYXNz") || strings.Contains(got, "\x1b") || !strings.Contains(got, "<masked>") {
		t.Fatalf("stderrのマスクまたは端末制御文字除去が不正: %q", got)
	}
}

func TestNoMaskIsRejectedForNonTerminalOutput(t *testing.T) {
	cfg := config.Defaults()
	cfg.Mask = false
	if _, err := enforceInteractiveMaskPolicy(cfg, &bytes.Buffer{}); err == nil {
		t.Fatal("redirect可能な非TTY出力で--no-maskを黙って受理した")
	}
}

func TestResolveSelectedPodUsesFreshObject(t *testing.T) {
	selected := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-1")}, Status: corev1.PodStatus{Phase: corev1.PodPending}}
	fresh := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-1")}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}

	got, err := resolveSelectedPod([]corev1.Pod{fresh}, selected)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != corev1.PodRunning {
		t.Fatalf("選択時の古いPod状態を使用した: phase=%s", got.Status.Phase)
	}
	got.Status.Phase = corev1.PodFailed
	if fresh.Status.Phase != corev1.PodRunning {
		t.Fatal("返却Podがスナップショットを共有している")
	}
}

func TestResolveSelectedPodRejectsDeletedOrRecreatedTarget(t *testing.T) {
	selected := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-1")}}
	if _, err := resolveSelectedPod(nil, selected); err == nil {
		t.Fatal("削除済みPodを診断対象として受理した")
	}
	recreated := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "api", UID: types.UID("pod-2")}}
	if _, err := resolveSelectedPod([]corev1.Pod{recreated}, selected); err == nil {
		t.Fatal("同名で再作成された別UIDのPodを診断対象として受理した")
	}
}

func TestPodSearchSeparatesNamespaceAndName(t *testing.T) {
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "api-worker"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "api-server"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "web"}},
	}
	filtered := filterPods(pods, "TEAM-B", "api")
	if len(filtered) != 1 || filtered[0].Namespace != "team-b" || filtered[0].Name != "api-server" {
		t.Fatalf("namespaceとPod名を独立検索できない: %#v", filtered)
	}
	if got := filterPods(pods, "api", ""); len(got) != 0 {
		t.Fatalf("Pod名がnamespace検索へ混入した: %#v", got)
	}
}

func TestPromptPodUsesFilteredSortedArrowSelection(t *testing.T) {
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "api-z"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "api-a"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "api-m"}},
	}
	input, output := strings.NewReader("nteam-b\n/api\n\x1b[B\r"), &bytes.Buffer{}
	cfg := config.Defaults()
	runner := &Runner{
		Config: cfg, Streams: Streams{In: input, Out: output, Err: output},
		Clients: &kube.Clients{Context: "test"}, Console: console.New(cfg, output, output),
	}
	selected, quit, err := runner.promptPod(pods)
	if err != nil || quit || selected == nil {
		t.Fatalf("Pod選択に失敗: selected=%#v quit=%v err=%v", selected, quit, err)
	}
	if selected.Namespace != "team-b" || selected.Name != "api-z" {
		t.Fatalf("表示順と矢印選択が一致しない: %#v", selected)
	}
	if !strings.Contains(output.String(), "Namespace検索") || !strings.Contains(output.String(), "Pod名検索") || !strings.Contains(output.String(), "↑/↓: 選択") {
		t.Fatalf("検索欄が分離表示されない: %q", output.String())
	}
	if strings.Contains(output.String(), "番号で選択") {
		t.Fatalf("番号入力UIが残っている: %q", output.String())
	}
}

func TestPromptPodCanRecoverFromNoMatchesInsideList(t *testing.T) {
	pods := []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "team-b", Name: "api"}}}
	input, output := strings.NewReader("/missing\n/api\n\r"), &bytes.Buffer{}
	cfg := config.Defaults()
	runner := &Runner{
		Config: cfg, Streams: Streams{In: input, Out: output, Err: output},
		Clients: &kube.Clients{Context: "test"}, Console: console.New(cfg, output, output),
	}
	selected, quit, err := runner.promptPod(pods)
	if err != nil || quit || selected == nil || selected.Name != "api" {
		t.Fatalf("一覧内で検索条件を修正できない: selected=%#v quit=%v err=%v", selected, quit, err)
	}
	if !strings.Contains(output.String(), "一致するPodがありません") {
		t.Fatalf("0件状態を一覧内に表示していない: %q", output.String())
	}
}

func TestPodSelectionKeysAndAlternateScreenCleanup(t *testing.T) {
	for _, test := range []struct {
		sequence string
		want     podSelectionAction
	}{
		{"\x1b[A", podSelectionUp},
		{"\x1b[B", podSelectionDown},
		{"\x1b[H", podSelectionHome},
		{"\x1b[F", podSelectionEnd},
		{"\x1b[5~", podSelectionPageUp},
		{"\x1b[6~", podSelectionPageDown},
		{"\x1b[C", podSelectionChoose},
		{"\x1b[D", podSelectionNone},
		{"\x1b[<64;12;8M", podSelectionUp},
		{"\x1b[<65;12;8M", podSelectionDown},
		{"\x1b[M" + string([]byte{96, 33, 33}), podSelectionUp},
		{"\x1b[M" + string([]byte{97, 33, 33}), podSelectionDown},
		{"\r", podSelectionChoose},
		{" ", podSelectionToggle},
		{"n", podSelectionNamespaceSearch},
		{"/", podSelectionNameSearch},
		{"c", podSelectionClearSearch},
		{"b", podSelectionBack},
		{"q", podSelectionQuit},
	} {
		got, err := readPodSelectionSequence(bufio.NewReader(strings.NewReader(test.sequence)))
		if err != nil || got != test.want {
			t.Fatalf("key %q: action=%v, want=%v, err=%v", test.sequence, got, test.want, err)
		}
	}

	output := &bytes.Buffer{}
	screen := &podSelectionScreen{output: output, alternate: true, height: 24}
	if err := screen.open(); err != nil {
		t.Fatal(err)
	}
	if err := screen.cursor(false); err != nil {
		t.Fatal(err)
	}
	screen.close()
	got := output.String()
	if !strings.Contains(got, "\x1b[?1049h") || !strings.Contains(got, "\x1b[?1049l") || !strings.HasSuffix(got, "\x1b[?25h\x1b[?1049l") {
		t.Fatalf("選択画面が終了時に復元されない: %q", got)
	}
}

func TestPodSelectionViewportLeavesRoomForFooterAndNotice(t *testing.T) {
	screen := &podSelectionScreen{alternate: true, height: 24}
	if got := screen.pageSize(20, false); got != 4 {
		t.Fatalf("通常時のPod表示件数=%d, want 4", got)
	}
	if got := screen.pageSize(20, true); got != 3 {
		t.Fatalf("通知表示時のPod表示件数=%d, want 3", got)
	}
}

func TestPodSelectionRowsFitWithinTerminalWidth(t *testing.T) {
	rows := []console.TableRow{
		{
			Cells: []string{
				"▶",
				"troubleshooting-with-a-long-namespace",
				"kube-controller-manager-troubleshooting-control-plane-with-a-long-suffix",
				"1/1",
				"CrashLoopBackOff",
			},
			Status: "CrashLoopBackOff", Selected: true,
		},
	}
	const terminalWidth = 56
	fitted := fitSelectionPodRows(rows, terminalWidth)
	output := &bytes.Buffer{}
	cfg := config.Defaults()
	console.New(cfg, output, output).PodTable(podSelectionHeaders, fitted)
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if width := console.DisplayWidth(line); width > terminalWidth {
			t.Fatalf("Pod選択行が端末幅を超えています: width=%d line=%q", width, line)
		}
	}
	if !strings.Contains(output.String(), "…") || !fitted[0].Selected {
		t.Fatalf("長い値の省略または選択状態の保持に失敗しました: %#v output=%q", fitted, output.String())
	}
}

func TestMenuViewportScrollsBeforeTheFifthItem(t *testing.T) {
	output := &bytes.Buffer{}
	cfg := config.Defaults()
	session := newWizardSession(cfg, Streams{In: strings.NewReader(""), Out: output, Err: output})
	session.screen = &podSelectionScreen{output: output, alternate: true, height: 24}
	items := make([]wizardItem, 8)
	for index := range items {
		items[index] = wizardItem{Label: fmt.Sprintf("項目%d", index+1), Description: fmt.Sprintf("説明%d", index+1)}
	}
	if err := session.drawMenu("表示テスト", "", items, 4, nil, true); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, "▶  項目5") || !strings.Contains(got, "表示 3-6 / 8件") {
		t.Fatalf("5行目へ移動した表示範囲が不正: %q", got)
	}
	if strings.Contains(got, "項目1") {
		t.Fatalf("画面高を超える先頭行が残っている: %q", got)
	}
	if strings.Contains(got, "←") || !strings.Contains(got, "b: 1つ戻る  q: 終了") {
		t.Fatalf("戻る操作がb以外にも割り当てられている: %q", got)
	}
}

func TestRootMenuShowsAllEightEntriesOnAStandardTerminal(t *testing.T) {
	output := &bytes.Buffer{}
	cfg := config.Defaults()
	session := newWizardSession(cfg, Streams{In: strings.NewReader(""), Out: output, Err: output})
	session.screen = &podSelectionScreen{output: output, alternate: true, height: 23}
	items := []wizardItem{
		{Label: "クラスタ全体", Description: "全体診断"},
		{Label: "Podを1つ選んで詳しく", Description: "個別診断"},
		{Label: "Pod一覧だけ", Description: "一覧"},
		{Label: "quick", Description: "短時間"},
		{Label: "ci", Description: "CI"},
		{Label: "deep", Description: "詳細"},
		{Label: "設定を変更する", Description: "設定"},
		{Label: "終了", Description: "終了"},
	}
	if err := session.drawMenu(rootWizardTitle, "説明", items, len(items)-1, nil, false); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, item := range items {
		if !strings.Contains(got, item.Label) {
			t.Fatalf("ルートメニューに%qが表示されない: %q", item.Label, got)
		}
	}
	if strings.Contains(got, "表示 ") {
		t.Fatalf("8件のルートメニューがページ分割された: %q", got)
	}
	if lines := strings.Count(got, "\n"); lines > session.screen.height {
		t.Fatalf("ルートメニューが端末高を超えた: lines=%d height=%d output=%q", lines, session.screen.height, got)
	}
}

func TestGuidedMenuBuildsAllModeWithoutChangingDiagnosisEngine(t *testing.T) {
	// Enter selects all; three Down keys reach "next"; Enter confirms extras;
	// the final Enter starts diagnosis.
	input := strings.NewReader("\r\x1b[B\x1b[B\x1b[B\r\r")
	output := &bytes.Buffer{}
	cfg, quit, err := Guide(config.Defaults(), Streams{In: input, Out: output, Err: output})
	if err != nil || quit {
		t.Fatalf("ガイドを完了できない: quit=%v err=%v output=%q", quit, err, output.String())
	}
	if cfg.Mode != "all" || cfg.ShowLogs || cfg.ShowUnused || cfg.Debug {
		t.Fatalf("選択内容とConfigが一致しない: %#v", cfg)
	}
	if !strings.Contains(output.String(), "何を診断しますか") || !strings.Contains(output.String(), "クラスタ全体 — 追加で行う診断") {
		t.Fatalf("段階式メニューが表示されない: %q", output.String())
	}
}

func TestGuidedMenuHidesDebugWhenCurrentOutputCannotUseIt(t *testing.T) {
	base := config.Defaults()
	base.Output = "json"
	input := strings.NewReader("\r\x1b[B\x1b[B\r\r")
	output := &bytes.Buffer{}
	cfg, quit, err := Guide(base, Streams{In: input, Out: output, Err: output})
	if err != nil || quit {
		t.Fatalf("構造化出力のガイドを完了できない: quit=%v err=%v output=%q", quit, err, output.String())
	}
	if cfg.Output != "json" || cfg.Debug {
		t.Fatalf("構造化出力へ無効なdebugを混入した: %#v", cfg)
	}
	if strings.Contains(output.String(), "診断後にdebugメニューを開く") {
		t.Fatalf("無効なdebug選択肢を表示した: %q", output.String())
	}
}

func TestGuidedPodConnectionPromptsOnlyAfterSelection(t *testing.T) {
	input := strings.NewReader(
		"\x1b[B\r" + // Pod個別
			"\r\x1b[B\x1b[B\x1b[B\r" + // 接続確認をONにして次へ
			"70000\n18080\n/ready\n" + // 不正値を拒否して接続詳細を再入力
			"\r", // 実行
	)
	output := &bytes.Buffer{}
	cfg, quit, err := Guide(config.Defaults(), Streams{In: input, Out: output, Err: output})
	if err != nil || quit {
		t.Fatalf("Pod接続ガイドを完了できない: quit=%v err=%v output=%q", quit, err, output.String())
	}
	if cfg.Mode != "select" || !cfg.Connect || cfg.ConnectPort != 18080 || cfg.ConnectPath != "/ready" {
		t.Fatalf("接続設定がConfigへ反映されない: %#v", cfg)
	}
	if !strings.Contains(output.String(), "接続確認の設定") {
		t.Fatalf("選択した追加機能の詳細が表示されない: %q", output.String())
	}
	for _, expected := range []string{"注意: 一時port-forward", "追加確認なしで実行します"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("接続確認の選択欄に注意書き%qがない: %q", expected, output.String())
		}
	}
	if !strings.Contains(output.String(), "65535") {
		t.Fatalf("不正値の理由を示して再入力させていない: %q", output.String())
	}
}

func TestGuidedDetailsCanReturnExactlyOneStep(t *testing.T) {
	input := strings.NewReader(
		"\x1b[B\r" + // Pod個別
			"\r\x1b[F\r" + // 接続確認をONにして次へ
			"18080\nb\n19090\n/healthz\n" + // pathからportへ1つ戻る
			"\r", // 実行
	)
	output := &bytes.Buffer{}
	cfg, quit, err := Guide(config.Defaults(), Streams{In: input, Out: output, Err: output})
	if err != nil || quit {
		t.Fatalf("直前の詳細設定へ戻れない: quit=%v err=%v output=%q", quit, err, output.String())
	}
	if cfg.ConnectPort != 19090 || cfg.ConnectPath != "/healthz" {
		t.Fatalf("戻った後の設定が反映されない: %#v", cfg)
	}
	if strings.Count(output.String(), "ローカルポート") < 2 {
		t.Fatalf("HTTPパスからローカルポートへ戻っていない: %q", output.String())
	}
}

func TestGuidedConfirmationReturnsToLastDetail(t *testing.T) {
	input := strings.NewReader(
		"\x1b[B\r" + // Pod個別
			"\r\x1b[F\r" + // 接続確認をONにして次へ
			"18080\n/ready\n" +
			"b" + // 確認画面から1つ前へ
			"/live\n" + // 直前のHTTPパスだけを再編集
			"\r", // 実行
	)
	output := &bytes.Buffer{}
	cfg, quit, err := Guide(config.Defaults(), Streams{In: input, Out: output, Err: output})
	if err != nil || quit {
		t.Fatalf("確認画面から直前の詳細へ戻れない: quit=%v err=%v output=%q", quit, err, output.String())
	}
	if cfg.ConnectPort != 18080 || cfg.ConnectPath != "/live" {
		t.Fatalf("最後の詳細だけを再編集できない: %#v", cfg)
	}
	if strings.Count(output.String(), "│ ローカルポート") != 1 || strings.Count(output.String(), "│ HTTPパス") < 2 {
		t.Fatalf("確認画面から戻る位置が不正: %q", output.String())
	}
	if strings.Contains(output.String(), "1つ前の画面へ戻る") {
		t.Fatalf("戻る操作が選択項目として残っている: %q", output.String())
	}
}

func TestGuidedMenuCanQuitWithoutRunning(t *testing.T) {
	output := &bytes.Buffer{}
	_, quit, err := Guide(config.Defaults(), Streams{In: strings.NewReader("q"), Out: output, Err: output})
	if err != nil || !quit {
		t.Fatalf("qで正常終了できない: quit=%v err=%v", quit, err)
	}
}

func TestQQuitsInsteadOfReturningFromNestedMenu(t *testing.T) {
	output := &bytes.Buffer{}
	_, quit, err := Guide(config.Defaults(), Streams{In: strings.NewReader("\rq"), Out: output, Err: output})
	if err != nil || !quit {
		t.Fatalf("追加設定画面のqで終了できない: quit=%v err=%v", quit, err)
	}
	if strings.Count(output.String(), "何を診断しますか？") != 1 {
		t.Fatalf("qが戻る操作として処理された: %q", output.String())
	}
}

func TestSettingsEditorSavesWithTheSharedINIValidation(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	// Target category, namespace, value. Enterで値を確定した時点で保存し、
	// bでカテゴリ、さらにbで設定エディタを閉じる。
	input := strings.NewReader("\r\rproduction\nbb")
	output := &bytes.Buffer{}
	updated, saved, quit, err := EditSettings(config.Defaults(), Streams{In: input, Out: output, Err: output})
	if err != nil || quit {
		t.Fatalf("設定を保存できない: quit=%v err=%v output=%q", quit, err, output.String())
	}
	if updated.Namespace != "production" || saved != filepath.Join(directory, config.DefaultConfigFilename) {
		t.Fatalf("対話設定が保存結果へ反映されない: cfg=%#v saved=%q", updated, saved)
	}
	for _, removed := range []string{"保存先:", "カテゴリ一覧へ戻る", "変更を破棄して戻る"} {
		if strings.Contains(output.String(), removed) {
			t.Fatalf("不要な操作が選択項目として残っている: %q", output.String())
		}
	}
	reloaded, err := config.Parse(nil, "k8s-diagnose")
	if err != nil || reloaded.Namespace != "production" {
		t.Fatalf("保存した既定INIを自動再読込できない: cfg=%#v err=%v", reloaded, err)
	}
}

func TestSettingsEditorBooleanUsesSelectionAndSavesImmediately(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	input := strings.NewReader(
		strings.Repeat("\x1b[B", 4) + "\r" + // 表示カテゴリ
			strings.Repeat("\x1b[B", 4) + "\r" + // 実API要求
			"\x1b[A\r" + // 既定値から「無効」に移動して確定
			"bb", // 表示カテゴリ、設定エディタの順に戻る
	)
	output := &bytes.Buffer{}
	updated, saved, quit, err := EditSettings(config.Defaults(), Streams{In: input, Out: output, Err: output})
	if err != nil || quit {
		t.Fatalf("真偽値を選択して保存できない: quit=%v err=%v output=%q", quit, err, output.String())
	}
	if updated.ShowAPIRequests || !updated.SettingExplicit("display.show_api_requests") {
		t.Fatalf("選択した真偽値が反映されない: %#v", updated)
	}
	if saved != filepath.Join(directory, config.DefaultConfigFilename) {
		t.Fatalf("Enter確定時の保存先=%q", saved)
	}
	reloaded, err := config.Parse(nil, "k8s-diagnose")
	if err != nil || reloaded.ShowAPIRequests || !reloaded.SettingExplicit("display.show_api_requests") {
		t.Fatalf("自動保存した真偽値を再読込できない: cfg=%#v err=%v", reloaded, err)
	}
	for _, expected := range []string{"有効にする (true)", "無効にする (false)", "組み込み既定値に戻す", "設定を保存しました"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("真偽値選択画面または保存通知に%qがない: %q", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "末尾に実行したKubernetes API要求を表示 / 空Enter") {
		t.Fatalf("説明と操作が同じ行へ連結されている: %q", output.String())
	}
}

func TestSettingValuePromptRendersAllInformationInOneTable(t *testing.T) {
	output := &bytes.Buffer{}
	session := newWizardSession(config.Defaults(), Streams{In: strings.NewReader("\n"), Out: output, Err: output})
	value, canceled, err := session.promptValue("Namespace", "target.namespace", "default", "空欄なら全Namespace")
	if err != nil || canceled || value != "" {
		t.Fatalf("値入力を終了できない: value=%q canceled=%v err=%v", value, canceled, err)
	}
	for _, expected := range []string{
		"│ 設定項目", "│ 説明", "│ 現在値", "│ 入力値", "入力（Enterで確定）\n",
		"│ 空欄", "│ -", "│ b", "組み込み既定値に戻す", "1つ前へ戻る",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("値入力画面に%qがない: %q", expected, output.String())
		}
	}
	for _, separatedHeading := range []string{"  設定項目\n", "  説明\n", "  現在値\n", "  操作（Enterで確定）\n"} {
		if strings.Contains(output.String(), separatedHeading) {
			t.Fatalf("設定情報が表外の見出し%qへ分離されています: %q", separatedHeading, output.String())
		}
	}
	for _, old := range []string{"空のまま Enter      :", "- を入力して Enter :", "b を入力して Enter :"} {
		if strings.Contains(output.String(), old) {
			t.Fatalf("操作説明に旧コロン区切り%qが残っている: %q", old, output.String())
		}
	}
	tableRows := []string{}
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "  │") {
			tableRows = append(tableRows, line)
		}
	}
	if len(tableRows) != 7 {
		t.Fatalf("設定表の行数=%d, want 7: %q", len(tableRows), output.String())
	}
	leftWidth, rightWidth := -1, -1
	for _, line := range tableRows {
		cells := strings.Split(line, "│")
		if len(cells) != 4 {
			t.Fatalf("設定表の罫線が不正です: %q", line)
		}
		if leftWidth < 0 {
			leftWidth, rightWidth = console.DisplayWidth(cells[1]), console.DisplayWidth(cells[2])
			continue
		}
		if console.DisplayWidth(cells[1]) != leftWidth || console.DisplayWidth(cells[2]) != rightWidth {
			t.Fatalf("全角文字を含む設定表の列幅が揃っていません: %q", tableRows)
		}
	}
}

func TestWrapPromptCellUsesTerminalDisplayWidth(t *testing.T) {
	lines := wrapPromptCell("HTTPパスは/readyを指定します", 12)
	if len(lines) < 2 {
		t.Fatalf("長い説明が折り返されていません: %q", lines)
	}
	if strings.Join(lines, "") != "HTTPパスは/readyを指定します" {
		t.Fatalf("折返しで説明が変化しました: %q", lines)
	}
	for _, line := range lines {
		if width := console.DisplayWidth(line); width > 12 {
			t.Fatalf("折返し後の表示幅=%d, want <= 12: %q", width, line)
		}
	}
}

func TestDiscardWizardEscapeSequenceConsumesScrollingAndCursorInput(t *testing.T) {
	tests := []struct {
		name     string
		sequence string
	}{
		{name: "arrow", sequence: "[A"},
		{name: "sgr mouse wheel", sequence: "[<64;12;8M"},
		{name: "ss3 cursor", sequence: "OA"},
		{name: "osc", sequence: "]0;terminal title\a"},
		{name: "x10 mouse wheel", sequence: "[Mabc"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(test.sequence + "remaining"))
			if err := discardWizardEscapeSequence(reader); err != nil {
				t.Fatalf("制御シーケンスを読み捨てられない: %v", err)
			}
			remaining, err := io.ReadAll(reader)
			if err != nil || string(remaining) != "remaining" {
				t.Fatalf("通常入力まで消費しました: remaining=%q err=%v", remaining, err)
			}
		})
	}
}

func TestFailedAutomaticSaveDoesNotChangeTheCandidate(t *testing.T) {
	cfg := config.Defaults()
	cfg.ConfigFile = t.TempDir() // ファイルではなく既存ディレクトリなのでrenameに失敗する。
	var spec config.SettingSpec
	for _, candidate := range settingsForSection("display") {
		if candidate.Name == "display.show_api_requests" {
			spec = candidate
			break
		}
	}
	if spec.Name == "" {
		t.Fatal("実API要求の設定定義がない")
	}
	updated, saved, err := persistPromptedSetting(cfg, spec, "false")
	if err == nil {
		t.Fatal("保存できないパスを成功扱いした")
	}
	if saved != "" || updated.ShowAPIRequests != cfg.ShowAPIRequests || updated.SettingExplicit(spec.Name) {
		t.Fatalf("保存失敗した値が候補へ反映された: updated=%#v saved=%q", updated, saved)
	}
}

func TestSettingsEditorModeChangeClearsOptionsThatWouldBecomeMeaningless(t *testing.T) {
	cfg := config.Defaults()
	var err error
	cfg, err = cfg.WithSetting("diagnosis.logs", "true")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := applyPromptedSetting(cfg, "diagnosis.mode", "select")
	if err != nil {
		t.Fatalf("モード変更を安全な設定へ絞り込めない: %v", err)
	}
	if updated.Mode != "select" || updated.ShowLogs || !updated.SettingExplicit("diagnosis.mode") {
		t.Fatalf("モードまたは従属設定が不正: %#v", updated)
	}
}

func TestCommandDisplayIsPlacedBesideItsDiagnosticItem(t *testing.T) {
	output := &bytes.Buffer{}
	cfg := config.Defaults()
	cfg.Kubeconfig = "/tmp/cluster config"
	runner := &Runner{Config: cfg, Streams: Streams{Out: output, Err: output}, Console: console.New(cfg, output, output)}
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["pods"] = kube.FetchStatus{Available: true}
	runner.Console.Chapter("Pod一覧")
	runner.renderCommandsForKeys(snapshot, "pods")
	runner.Console.Write("Pod一覧の診断結果")
	finding := model.NewFinding(model.Issue, "K8S.POD.FAILED_PHASE", "Pod", "Pod/prod/api", "Failed", "phase", "Pod prod/api はFailedです", 100)
	state := model.NewState()
	state.Add(finding)
	runner.Console.Summary(state, func(value model.Finding) {
		runner.renderCommandsForFinding(snapshot, value)
	})
	got := output.String()
	for _, expected := range []string{"Pod一覧", "kubectl --kubeconfig '/tmp/cluster config'", "get pods -A", "get pod api -n prod -o json"} {
		if !strings.Contains(got, expected) {
			t.Fatalf("コマンド表示に%qがない: %q", expected, got)
		}
	}
	if strings.Contains(got, "この診断を手動確認するkubectl") {
		t.Fatalf("不要な確認コマンド案内が残っている: %q", got)
	}
	if strings.Index(got, "get pods -A") > strings.Index(got, "Pod一覧の診断結果") || strings.Index(got, "get pod api -n prod") > strings.Index(got, "Pod prod/api はFailedです") {
		t.Fatalf("確認コマンドが対応する診断結果より後に表示された: %q", got)
	}
	if strings.Contains(got, "--limit") {
		t.Fatalf("無効なkubectlフラグが表示された: %q", got)
	}
}

func TestRenderTextKeepsCommandsOutOfThePreambleAndTraceAtTheEnd(t *testing.T) {
	output := &bytes.Buffer{}
	cfg := config.Defaults()
	cfg.Mode = "all"
	runner := &Runner{
		Config:  cfg,
		Streams: Streams{Out: output, Err: output},
		Clients: &kube.Clients{Context: "test-context"},
		Console: console.New(cfg, output, output),
		trace:   &bytes.Buffer{},
	}
	runner.trace.WriteString("GET /api/v1/pods\n")
	snapshot := kube.NewSnapshot()
	snapshot.Statuses["pods"] = kube.FetchStatus{Available: true}
	snapshot.Pods = []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "prod"}}}
	runner.renderText(snapshot, model.NewState())

	got := output.String()
	podHeading := strings.Index(got, "Pod一覧")
	podTable := strings.Index(got, "NAMESPACE")
	command := strings.Index(got, "$ kubectl")
	trace := strings.Index(got, "実行したKubernetes API要求")
	health := strings.Index(got, "Health:")
	if podHeading < 0 || podTable < 0 || command < 0 || command < podHeading || command > podTable {
		t.Fatalf("kubectlが冒頭へ一括表示された、またはPod項目に紐付いていない: %q", got)
	}
	if trace < 0 || health < 0 || trace < health {
		t.Fatalf("実API要求の技術情報が診断結果より前に表示された: %q", got)
	}

	withoutCommands := &bytes.Buffer{}
	cfg.ShowCmd = false
	cfg.ShowAPIRequests = false
	runner.Config = cfg
	runner.Console = console.New(cfg, withoutCommands, withoutCommands)
	runner.Streams = Streams{Out: withoutCommands, Err: withoutCommands}
	runner.trace = &bytes.Buffer{}
	runner.trace.WriteString("GET /api/v1/pods\n")
	runner.renderText(snapshot, model.NewState())
	if strings.Contains(withoutCommands.String(), "kubectl") || strings.Contains(withoutCommands.String(), "実行したKubernetes API要求") {
		t.Fatalf("--no-cmd相当でコマンド情報が表示された: %q", withoutCommands.String())
	}

	commandsOnly := &bytes.Buffer{}
	cfg.ShowCmd = true
	cfg.ShowAPIRequests = false
	runner.Config = cfg
	runner.Console = console.New(cfg, commandsOnly, commandsOnly)
	runner.Streams = Streams{Out: commandsOnly, Err: commandsOnly}
	runner.trace = &bytes.Buffer{}
	runner.trace.WriteString("GET /api/v1/pods\n")
	runner.renderText(snapshot, model.NewState())
	if !strings.Contains(commandsOnly.String(), "$ kubectl") || strings.Contains(commandsOnly.String(), "実行したKubernetes API要求") || strings.Contains(commandsOnly.String(), "GET /api/v1/pods") {
		t.Fatalf("確認用kubectlを残したまま実API要求だけを非表示にできない: %q", commandsOnly.String())
	}
}

func TestRenderTextIncludesDiagnosticContents(t *testing.T) {
	output := &bytes.Buffer{}
	cfg := config.Defaults()
	cfg.Mode = "triage"
	cfg.ShowAPIRequests = false
	runner := &Runner{
		Config:  cfg,
		Streams: Streams{Out: output, Err: output},
		Clients: &kube.Clients{Context: "test-context"},
		Console: console.New(cfg, output, output),
	}
	state := model.NewState()
	state.AddCheck(model.Check{ID: "pod-health", Section: "Pod", Description: "Podとコンテナの稼働状態", Available: true})
	runner.renderText(kube.NewSnapshot(), state)

	got := output.String()
	if !strings.Contains(got, "診断内容（実施状況）") || !strings.Contains(got, "Podとコンテナの稼働状態") {
		t.Fatalf("テキスト診断結果に診断内容が表示されない: %q", got)
	}
	if strings.Index(got, "診断内容（実施状況）") > strings.Index(got, "クラスタ健全性スコア") {
		t.Fatalf("診断内容が結果末尾のスコアより後に表示された: %q", got)
	}
}

func TestReadyRatioIncludesNativeSidecar(t *testing.T) {
	restartAlways := corev1.ContainerRestartPolicyAlways
	pod := corev1.Pod{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "sidecar", RestartPolicy: &restartAlways}},
			Containers:     []corev1.Container{{Name: "app"}},
		},
		Status: corev1.PodStatus{
			InitContainerStatuses: []corev1.ContainerStatus{{Name: "sidecar", Ready: false}},
			ContainerStatuses:     []corev1.ContainerStatus{{Name: "app", Ready: true}},
		},
	}
	ready, total := readyRatio(&pod)
	if ready != 1 || total != 2 {
		t.Fatalf("ready=%d/%d, want 1/2", ready, total)
	}
}

func TestLogSelectionIncludesRunningButUnhealthyPods(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	readyTrue := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	readyFalse := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	base := corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: readyTrue, ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	cfg := config.Defaults()
	if !isHealthyPod(&base, cfg, now) {
		t.Fatal("ReadyなRunning Podを異常ログ対象にした")
	}
	notReady := base.DeepCopy()
	notReady.Status.Conditions = readyFalse
	if isHealthyPod(notReady, cfg, now) {
		t.Fatal("RunningだがReady=FalseのPodを健康扱いした")
	}
	restarted := base.DeepCopy()
	restarted.Status.ContainerStatuses[0].RestartCount = int32(cfg.RestartThreshold)
	restarted.Status.ContainerStatuses[0].LastTerminationState.Terminated = &corev1.ContainerStateTerminated{Reason: "Error", FinishedAt: metav1.NewTime(now.Add(-time.Hour))}
	if isHealthyPod(restarted, cfg, now) {
		t.Fatal("直近再起動が警告閾値に達したPodを健康扱いした")
	}
	ephemeralFailure := base.DeepCopy()
	ephemeralFailure.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "debug", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}}}}
	if !isHealthyPod(ephemeralFailure, cfg, now) {
		t.Fatal("debug用ephemeral containerの終了だけでPodを異常扱いした")
	}
}

func TestCollectedLogsAreIncludedInCoverage(t *testing.T) {
	cfg := config.Defaults()
	cfg.Mode = "select"
	runner := &Runner{
		Config:      cfg,
		Clients:     &kube.Clients{Kube: kubefake.NewSimpleClientset()},
		LogAnalyzer: mustLogAnalyzer(t, cfg.LogSignatureLines),
	}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	state := model.NewState()
	runner.collectLogs(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, state, true)
	ok, unavailable, total := state.CoverageCounts()
	if ok != 2 || unavailable != 0 || total != 2 {
		t.Fatalf("current/previousログのCoverage=%d/%d unavailable=%d", ok, total, unavailable)
	}
	if len(runner.kubectlCmds) != 2 {
		t.Fatalf("current/previousの確認用kubectl logsが記録されない: %#v", runner.kubectlCmds)
	}
}

func TestLogCommandsAreGeneratedPerContainer(t *testing.T) {
	cfg := config.Defaults()
	cfg.Mode = "select"
	runner := &Runner{Config: cfg, Clients: &kube.Clients{Kube: kubefake.NewSimpleClientset()}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "sidecar"}}},
	}
	_, _ = runner.podLogs(context.Background(), pod, false)
	if len(runner.kubectlCmds) != 2 {
		t.Fatalf("コンテナ別コマンド数=%d, want 2", len(runner.kubectlCmds))
	}
	first, second := strings.Join(runner.kubectlCmds[0], " "), strings.Join(runner.kubectlCmds[1], " ")
	if !strings.Contains(first, "-c app") || !strings.Contains(second, "-c sidecar") {
		t.Fatalf("コンテナ名がコマンドへ反映されない: %q / %q", first, second)
	}
}

func TestUnusedDiagnosticsExposePartialAcquisitionAndCoverage(t *testing.T) {
	snapshot := kube.NewSnapshot()
	for _, key := range []string{"pods", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs", "ingresses", "configmaps", "secrets", "pvcs", "serviceaccounts"} {
		snapshot.Statuses[key] = kube.FetchStatus{Available: true, Status: kube.StatusOK}
	}
	snapshot.Statuses["deployments"] = kube.FetchStatus{Available: false, Status: kube.StatusForbidden, Reason: "RBAC Forbidden"}
	snapshot.ConfigMaps = []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "ns"}}}
	state := model.NewState()
	addUnusedDiagnostics(snapshot, state, false)

	ok, unavailable, total := state.CoverageCounts()
	if ok != 11 || unavailable != 1 || total != 12 {
		t.Fatalf("未使用診断Coverage=%d/%d unavailable=%d", ok, total, unavailable)
	}
	foundGap, foundCandidate := false, false
	for _, finding := range state.Findings {
		if finding.RuleID != "unused" {
			t.Fatalf("未使用診断のrule_idが不正: %#v", finding)
		}
		foundGap = foundGap || finding.Code == "K8S.UNUSED.PARTIAL_UNAVAILABLE"
		foundCandidate = foundCandidate || finding.Code == "K8S.UNUSED.CANDIDATE" && finding.Resource == "ConfigMap/ns/settings"
	}
	if !foundGap || !foundCandidate {
		t.Fatalf("部分取得または取得範囲内候補が欠落: %#v", state.Findings)
	}
}

func mustLogAnalyzer(t *testing.T, lines int) *rules.LogAnalyzer {
	t.Helper()
	analyzer, err := rules.NewLogAnalyzer("", lines)
	if err != nil {
		t.Fatal(err)
	}
	return analyzer
}

func TestListSummaryUsesPodPhaseNotDisplayReason(t *testing.T) {
	pod := corev1.Pod{Status: corev1.PodStatus{
		Phase:             corev1.PodPending,
		ContainerStatuses: []corev1.ContainerStatus{{State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}}},
	}}
	counts := podPhaseCounts([]corev1.Pod{pod})
	if podStatus(&pod) != "ImagePullBackOff" || counts["Pending"] != 1 || counts["ImagePullBackOff"] != 0 {
		t.Fatalf("表示reasonをphase集計へ混入した: %#v", counts)
	}
}

func TestNewestBytesKeepsLogTailAndUTF8(t *testing.T) {
	value := "old\n" + string(make([]byte, 100)) + "\n直近のエラー"
	got := newestBytes(value, 30)
	if got == "" || got[len(got)-len("直近のエラー"):] != "直近のエラー" {
		t.Fatalf("最新ログが残っていない: %q", got)
	}
}

func TestNodeMetricRowsCalculateAllocatablePercentages(t *testing.T) {
	snapshot := &kube.Snapshot{
		Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}, Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("4Gi"),
		}}}},
		NodeMetrics: []unstructured.Unstructured{{Object: map[string]any{
			"metadata": map[string]any{"name": "node-a"},
			"usage":    map[string]any{"cpu": "1000m", "memory": "1Gi"},
		}}},
	}
	rows := nodeMetricRows(snapshot)
	if len(rows) != 1 || rows[0].Cells[2] != "50%" || rows[0].Cells[4] != "25%" {
		t.Fatalf("Node使用率が不正: %#v", rows)
	}
}

func TestMetricNotFoundIsReportedAsUnavailableAPI(t *testing.T) {
	got := fetchStatusText(kube.FetchStatus{Status: kube.StatusNotFound})
	if got != "Metrics APIが提供されていません（NotFound）" {
		t.Fatalf("NotFoundをAPI到達不能と誤表示した: %q", got)
	}
}

func TestPodMetricRowsSortCPUAndLimitTen(t *testing.T) {
	items := make([]unstructured.Unstructured, 0, 11)
	for index := 1; index <= 11; index++ {
		items = append(items, unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"namespace": "ns", "name": fmt.Sprintf("pod-%02d", index)},
			"containers": []any{
				map[string]any{"usage": map[string]any{"cpu": fmt.Sprintf("%dm", index), "memory": "1Mi"}},
				map[string]any{"usage": map[string]any{"cpu": "1m", "memory": "2Mi"}},
			},
		}})
	}
	rows := podMetricRows(items, 10)
	if len(rows) != 10 || rows[0].Cells[1] != "pod-11" || rows[0].Cells[2] != "12m" || rows[0].Cells[3] != "3Mi" {
		t.Fatalf("Podメトリクスの集計・順序・上限が不正: %#v", rows)
	}
	for _, row := range rows {
		if row.Cells[1] == "pod-01" {
			t.Fatalf("CPU最下位Podが上位10件へ残った: %#v", rows)
		}
	}
}
