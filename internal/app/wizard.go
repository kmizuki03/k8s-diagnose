package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"golang.org/x/term"
)

type wizardItem struct {
	Label       string
	Description string
}

type wizardSession struct {
	streams Streams
	reader  *bufio.Reader
	screen  *podSelectionScreen
	console *console.Console
	config  config.Config
	notice  string
}

var errWizardQuit = errors.New("対話メニューを終了します")

const rootWizardTitle = "何を診断しますか？"

// InteractiveTerminal reports whether both input and output support the
// terminal controls required by the guided menu. Piped invocations retain the
// historical non-interactive default instead of waiting for input.
func InteractiveTerminal(streams Streams) bool {
	input, inputOK := streams.In.(*os.File)
	output, outputOK := streams.Out.(*os.File)
	if !inputOK || !outputOK {
		return false
	}
	inputFD := int(input.Fd())   // #nosec G115 -- canonical x/term descriptor conversion.
	outputFD := int(output.Fd()) // #nosec G115 -- canonical x/term descriptor conversion.
	return term.IsTerminal(inputFD) && term.IsTerminal(outputFD)
}

func newWizardSession(cfg config.Config, streams Streams) *wizardSession {
	if streams.In == nil {
		streams.In = os.Stdin
	}
	if streams.Out == nil {
		streams.Out = os.Stdout
	}
	if streams.Err == nil {
		streams.Err = os.Stderr
	}
	return &wizardSession{
		streams: streams,
		reader:  bufio.NewReader(streams.In),
		screen:  newPodSelectionScreen(streams.In, streams.Out),
		console: console.New(cfg, streams.Out, streams.Err),
		config:  cfg,
	}
}

func (session *wizardSession) setConfig(cfg config.Config) {
	session.config = cfg
	session.console = console.New(cfg, session.streams.Out, session.streams.Err)
}

// Guide runs the no-argument, progressively disclosed entry point. It only
// creates a Config; collection and diagnosis remain in Run.
func Guide(base config.Config, streams Streams) (config.Config, bool, error) {
	session := newWizardSession(base, streams)
	defer session.screen.close()
	if err := session.screen.open(); err != nil {
		return base, false, fmt.Errorf("対話メニューを開始できません: %w", err)
	}

	for {
		choice, quit, err := session.choose(
			rootWizardTitle,
			"↑/↓で移動し、Enterで決定します。フラグを覚える必要はありません。",
			[]wizardItem{
				{"クラスタ全体", "対象範囲をまとめて診断し、必要な追加項目だけ選ぶ"},
				{"Podを1つ選んで詳しく", "Namespace・Pod名で検索して個別診断"},
				{"Pod一覧だけ", "Podの状態を一覧表示"},
				{"quick", config.CommandDescription("quick")},
				{"ci", config.CommandDescription("ci")},
				{"deep", config.CommandDescription("deep")},
				{"設定を変更する", "現在値を見ながらk8s-diagnose.iniを編集・保存"},
				{"終了", "何も実行せず終了"},
			},
			false,
		)
		if errors.Is(err, errWizardQuit) {
			return base, true, nil
		}
		if err != nil {
			return base, false, err
		}
		if quit || choice == 7 {
			return base, true, nil
		}
		if choice == 6 {
			updated, saved, _, err := session.editSettings(base)
			if errors.Is(err, errWizardQuit) {
				return base, true, nil
			}
			if err != nil {
				return base, false, err
			}
			base = updated
			session.setConfig(base)
			if saved != "" {
				session.notice = "設定を保存しました: " + saved
			}
			continue
		}

		profiles := []string{"all", "pod", "list", "quick", "ci", "deep"}
		candidate, err := config.ApplyProfile(base, profiles[choice])
		if err != nil {
			session.notice = err.Error()
			continue
		}
		var details []guidedSetting
		resumeDetails := false
		for {
			session.setConfig(candidate)
			back := false
			if resumeDetails && len(details) > 0 {
				candidate, back, err = session.runGuidedSettingsFrom(candidate, details, len(details)-1)
				if back {
					// Backing through the first detail reaches the option list.
					resumeDetails = false
					continue
				}
			} else {
				switch choice {
				case 0:
					candidate, details, back, err = session.configureAll(candidate)
				case 1:
					candidate, details, back, err = session.configurePod(candidate)
				}
			}
			if errors.Is(err, errWizardQuit) {
				return base, true, nil
			}
			if err != nil {
				return base, false, err
			}
			if back {
				break
			}
			session.setConfig(candidate)
			confirmed, err := session.confirm(candidate)
			if errors.Is(err, errWizardQuit) {
				return base, true, nil
			}
			if err != nil {
				return base, false, err
			}
			if confirmed {
				return candidate, false, nil
			}
			// Presets and list mode have no intermediate screen to revisit.
			if choice != 0 && choice != 1 {
				break
			}
			// Confirmation follows the final detail. Return there first; if no
			// detail exists, the options screen is the immediate predecessor.
			resumeDetails = len(details) > 0
		}
		session.setConfig(base)
	}
}

// EditSettings opens the same settings editor used by the no-argument guide.
// It intentionally delegates parsing and validation to config.WithSetting.
func EditSettings(base config.Config, streams Streams) (config.Config, string, bool, error) {
	session := newWizardSession(base, streams)
	defer session.screen.close()
	if err := session.screen.open(); err != nil {
		return base, "", false, fmt.Errorf("設定メニューを開始できません: %w", err)
	}
	updated, saved, canceled, err := session.editSettings(base)
	if errors.Is(err, errWizardQuit) {
		return base, "", true, nil
	}
	return updated, saved, canceled, err
}

func (session *wizardSession) configureAll(cfg config.Config) (config.Config, []guidedSetting, bool, error) {
	items := []wizardItem{
		{"失敗Podのログも見る", "--logs: 失敗コンテナの末尾ログを確認"},
		{"未使用候補も探す", "--unused: ConfigMap・Secret・PVC等の候補を確認"},
	}
	initial := []bool{cfg.ShowLogs, cfg.ShowUnused}
	debugIndex := -1
	if cfg.Output == "text" && cfg.Watch == 0 {
		debugIndex = len(items)
		items = append(items, wizardItem{"診断後にdebugメニューを開く", "--debug: 選択したPodでkubectl debugを案内"})
		initial = append(initial, cfg.Debug)
	}
	values := initial
	for {
		selected, back, err := session.toggle(
			"クラスタ全体 — 追加で行う診断",
			"必要な項目だけSpaceまたはEnterで切り替え、最後の「次へ」を選びます。",
			items,
			values,
		)
		if err != nil || back {
			return cfg, nil, back, err
		}
		values = selected
		if cfg, err = setLogs(cfg, selected[0]); err != nil {
			return cfg, nil, false, err
		}
		if cfg, err = cfg.WithSetting("diagnosis.unused", boolText(selected[1])); err != nil {
			return cfg, nil, false, err
		}
		debugEnabled := false
		if debugIndex >= 0 {
			debugEnabled = selected[debugIndex]
			if cfg, err = setDebug(cfg, debugEnabled); err != nil {
				return cfg, nil, false, err
			}
		}
		session.setConfig(cfg)
		details := make([]guidedSetting, 0, 3)
		if selected[0] && cfg.Output == "text" {
			details = append(details, guidedSetting{"display.tail", "ログ表示の設定", "表示する末尾行数", "1以上の行数を指定します"})
		}
		if debugEnabled {
			details = append(details,
				guidedSetting{"debug.image", "debugの設定", "debug image", "例: busybox:1.36"},
				guidedSetting{"debug.profile", "debugの設定", "debug profile", "例: general"},
			)
		}
		cfg, back, err = session.runGuidedSettings(cfg, details)
		if err != nil {
			return cfg, nil, false, err
		}
		if back {
			continue
		}
		return cfg, details, false, nil
	}
}

func (session *wizardSession) configurePod(cfg config.Config) (config.Config, []guidedSetting, bool, error) {
	items := []wizardItem{
		{"接続確認", "注意: 一時port-forwardを作成し、追加確認なしで実行します"},
		{"ログ表示行数を変更", "個別診断で表示するログ末尾行数を変更"},
		{"診断後にdebugメニューを開く", "確認後にkubectl debugの対話メニューを表示"},
	}
	values := []bool{cfg.Connect, cfg.SettingExplicit("display.tail"), cfg.Debug}
	for {
		selected, back, err := session.toggle(
			"Pod個別 — 追加で行う診断",
			"個別診断にはコンテナ状態・イベント・ログが含まれます。必要な追加操作だけ選びます。",
			items,
			values,
		)
		if err != nil || back {
			return cfg, nil, back, err
		}
		values = selected
		if cfg, err = setConnect(cfg, selected[0]); err != nil {
			return cfg, nil, false, err
		}
		if cfg, err = setDebug(cfg, selected[2]); err != nil {
			return cfg, nil, false, err
		}
		session.setConfig(cfg)
		details := make([]guidedSetting, 0, 5)
		if selected[1] {
			details = append(details, guidedSetting{"display.tail", "ログ表示の設定", "表示する末尾行数", "1以上の行数を指定します"})
		}
		if selected[0] {
			details = append(details,
				guidedSetting{"connection.port", "接続確認の設定", "ローカルポート", "1024〜65535。組み込み既定値では自動選択します"},
				guidedSetting{"connection.path", "接続確認の設定", "HTTPパス", "例: /ready。組み込み既定値ではProbe定義を使用します"},
			)
		}
		if selected[2] {
			details = append(details,
				guidedSetting{"debug.image", "debugの設定", "debug image", "例: busybox:1.36"},
				guidedSetting{"debug.profile", "debugの設定", "debug profile", "例: general"},
			)
		}
		cfg, back, err = session.runGuidedSettings(cfg, details)
		if err != nil {
			return cfg, nil, false, err
		}
		if back {
			continue
		}
		return cfg, details, false, nil
	}
}

type guidedSetting struct {
	name  string
	title string
	label string
	hint  string
}

// runGuidedSettings behaves like a small navigation stack. Going back from a
// detail returns to the previous detail; only the first detail returns to the
// option-selection screen.
func (session *wizardSession) runGuidedSettings(cfg config.Config, settings []guidedSetting) (config.Config, bool, error) {
	return session.runGuidedSettingsFrom(cfg, settings, 0)
}

func (session *wizardSession) runGuidedSettingsFrom(cfg config.Config, settings []guidedSetting, start int) (config.Config, bool, error) {
	if len(settings) == 0 {
		return cfg, false, nil
	}
	for index := max(0, min(start, len(settings)-1)); index < len(settings); {
		setting := settings[index]
		updated, back, err := session.promptSetting(cfg, setting.name, setting.title, setting.label, setting.hint)
		if err != nil {
			return cfg, false, err
		}
		if back {
			if index == 0 {
				return cfg, true, nil
			}
			index--
			continue
		}
		cfg = updated
		index++
	}
	return cfg, false, nil
}

func setLogs(cfg config.Config, enabled bool) (config.Config, error) {
	var err error
	if !enabled {
		for _, name := range []string{"diagnosis.log_signatures_file", "diagnosis.log_signature_lines", "display.tail"} {
			cfg, err = cfg.WithoutSetting(name)
			if err != nil {
				return cfg, err
			}
		}
	}
	return cfg.WithSetting("diagnosis.logs", boolText(enabled))
}

func setConnect(cfg config.Config, enabled bool) (config.Config, error) {
	var err error
	if !enabled {
		for _, name := range []string{"connection.port", "connection.path"} {
			cfg, err = cfg.WithoutSetting(name)
			if err != nil {
				return cfg, err
			}
		}
	}
	return cfg.WithSetting("connection.enabled", boolText(enabled))
}

func setDebug(cfg config.Config, enabled bool) (config.Config, error) {
	var err error
	if !enabled {
		for _, name := range []string{"debug.image", "debug.profile"} {
			cfg, err = cfg.WithoutSetting(name)
			if err != nil {
				return cfg, err
			}
		}
	}
	return cfg.WithSetting("debug.enabled", boolText(enabled))
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func applyPromptedSetting(cfg config.Config, name, value string) (config.Config, error) {
	if value == "-" {
		switch name {
		case "diagnosis.mode":
			updated, err := config.ApplyProfile(cfg, "all")
			if err != nil {
				return cfg, err
			}
			return updated.WithoutSetting(name)
		case "diagnosis.logs":
			updated, err := setLogs(cfg, false)
			if err != nil {
				return cfg, err
			}
			return updated.WithoutSetting(name)
		case "connection.enabled":
			updated, err := setConnect(cfg, false)
			if err != nil {
				return cfg, err
			}
			return updated.WithoutSetting(name)
		case "debug.enabled":
			updated, err := setDebug(cfg, false)
			if err != nil {
				return cfg, err
			}
			return updated.WithoutSetting(name)
		}
		return cfg.WithoutSetting(name)
	}
	if name == "diagnosis.mode" {
		command := map[string]string{"all": "all", "select": "pod", "list": "list", "triage": "triage"}[strings.ToLower(value)]
		if command != "" {
			updated, err := config.ApplyProfile(cfg, command)
			if err != nil {
				return cfg, err
			}
			return updated.WithSetting(name, strings.ToLower(value))
		}
	}
	switch strings.ToLower(value) {
	case "false", "no", "off", "0":
		switch name {
		case "diagnosis.logs":
			return setLogs(cfg, false)
		case "connection.enabled":
			return setConnect(cfg, false)
		case "debug.enabled":
			return setDebug(cfg, false)
		}
	}
	return cfg.WithSetting(name, value)
}

func (session *wizardSession) promptSetting(cfg config.Config, name, title, label, hint string) (config.Config, bool, error) {
	for {
		value, canceled, err := session.promptValue(title, label, cfg.SettingValue(name), hint)
		if err != nil || canceled {
			return cfg, canceled, err
		}
		if value == "" {
			return cfg, false, nil
		}
		updated, err := applyPromptedSetting(cfg, name, value)
		if err != nil {
			session.notice = err.Error()
			continue
		}
		session.setConfig(updated)
		return updated, false, nil
	}
}

func (session *wizardSession) confirm(cfg config.Config) (bool, error) {
	details := []string{
		"モード: " + cfg.Mode,
		"Namespace: " + cfg.ScopeLabel(),
		"出力: " + cfg.Output,
	}
	if cfg.ShowLogs {
		details = append(details, "失敗Podログ: あり")
	}
	if cfg.ShowUnused {
		details = append(details, "未使用候補: あり")
	}
	if cfg.Connect {
		details = append(details, "接続確認: あり")
	}
	if cfg.Debug {
		details = append(details, "debugメニュー: あり")
	}
	choice, back, err := session.choose("この内容で実行します", strings.Join(details, "  /  "), []wizardItem{
		{"診断を開始", "選択画面を閉じて診断を実行"},
	}, true)
	return !back && choice == 0, err
}

func (session *wizardSession) choose(title, description string, items []wizardItem, nested bool) (int, bool, error) {
	return session.chooseAt(title, description, items, nested, 0)
}

func (session *wizardSession) chooseAt(title, description string, items []wizardItem, nested bool, initial int) (int, bool, error) {
	if len(items) == 0 {
		return 0, false, errors.New("選択項目がありません")
	}
	selected := min(max(initial, 0), len(items)-1)
	for {
		if err := session.drawMenu(title, description, items, selected, nil, nested); err != nil {
			return 0, false, err
		}
		action, err := readPodSelectionKey(session.reader, session.streams.In)
		if err != nil {
			return 0, false, err
		}
		switch action {
		case podSelectionUp:
			selected = (selected - 1 + len(items)) % len(items)
		case podSelectionDown:
			selected = (selected + 1) % len(items)
		case podSelectionHome:
			selected = 0
		case podSelectionEnd:
			selected = len(items) - 1
		case podSelectionPageUp:
			selected = max(0, selected-session.screen.menuPageSize(len(items)))
		case podSelectionPageDown:
			selected = min(len(items)-1, selected+session.screen.menuPageSize(len(items)))
		case podSelectionChoose:
			return selected, false, nil
		case podSelectionBack:
			if nested {
				return 0, true, nil
			}
		case podSelectionQuit:
			return 0, false, errWizardQuit
		case podSelectionInterrupt:
			return 0, false, errPodSelectionInterrupted
		}
	}
}

func (session *wizardSession) toggle(title, description string, items []wizardItem, initial []bool) ([]bool, bool, error) {
	selected := 0
	values := append([]bool{}, initial...)
	menu := append(append([]wizardItem{}, items...), wizardItem{"次へ", "選択した内容で詳細設定へ進む"})
	for {
		if err := session.drawMenu(title, description, menu, selected, values, true); err != nil {
			return nil, false, err
		}
		action, err := readPodSelectionKey(session.reader, session.streams.In)
		if err != nil {
			return nil, false, err
		}
		switch action {
		case podSelectionUp:
			selected = (selected - 1 + len(menu)) % len(menu)
		case podSelectionDown:
			selected = (selected + 1) % len(menu)
		case podSelectionHome:
			selected = 0
		case podSelectionEnd:
			selected = len(menu) - 1
		case podSelectionPageUp:
			selected = max(0, selected-session.screen.menuPageSize(len(menu)))
		case podSelectionPageDown:
			selected = min(len(menu)-1, selected+session.screen.menuPageSize(len(menu)))
		case podSelectionChoose, podSelectionToggle:
			if selected == len(items) {
				return values, false, nil
			}
			values[selected] = !values[selected]
		case podSelectionBack:
			return values, true, nil
		case podSelectionQuit:
			return values, false, errWizardQuit
		case podSelectionInterrupt:
			return nil, false, errPodSelectionInterrupted
		}
	}
}

func (session *wizardSession) drawMenu(title, description string, items []wizardItem, selected int, toggles []bool, nested bool) error {
	if err := session.screen.cursor(false); err != nil {
		return err
	}
	if err := session.screen.clear(); err != nil {
		return err
	}
	rootMenu := title == rootWizardTitle
	headerConsole := session.console
	if rootMenu {
		displayConfig := session.config
		displayConfig.Mode = "guide"
		headerConsole = console.New(displayConfig, session.streams.Out, session.streams.Err)
	}
	headerConsole.Header("未接続")
	session.console.Chapter(title)
	if session.notice != "" {
		session.console.Write("  ▲ " + console.MaskSecrets(session.notice, true))
		session.notice = ""
	}
	if description != "" {
		for _, line := range strings.Split(description, "\n") {
			session.console.Write("  " + line)
		}
		if !rootMenu {
			session.console.Write()
		}
	}
	pageSize := session.screen.menuPageSize(len(items))
	if rootMenu {
		pageSize = session.screen.rootMenuPageSize(len(items))
	}
	start, end := selectionWindow(len(items), selected, pageSize)
	rows := make([]console.TableRow, 0, end-start)
	labelLimit := max(12, session.console.Width()-7)
	for index := start; index < end; index++ {
		item := items[index]
		marker := " "
		if index == selected {
			marker = "▶"
		}
		if toggles != nil && index < len(toggles) {
			checked := "[ ]"
			if toggles[index] {
				checked = "[✓]"
			}
			item.Label = checked + " " + item.Label
		}
		rows = append(rows, console.TableRow{Cells: []string{marker, console.TruncateDisplay(item.Label, labelLimit)}, Selected: index == selected})
	}
	session.console.Table([]string{"", "選択"}, rows, true)
	if start > 0 || end < len(items) {
		session.console.Write(fmt.Sprintf("  表示 %d-%d / %d件", start+1, end, len(items)))
	}
	if selected >= 0 && selected < len(items) && items[selected].Description != "" {
		detailLimit := max(10, session.console.Width()-8)
		warning := strings.HasPrefix(items[selected].Description, "注意:")
		if warning {
			detailLimit = max(10, detailLimit-2)
		}
		prefix := "\n  内容: "
		if rootMenu {
			prefix = "  内容: "
		}
		detail := prefix + console.TruncateDisplay(items[selected].Description, detailLimit)
		if warning {
			detail = prefix + "▲ " + console.TruncateDisplay(items[selected].Description, detailLimit)
			detail = session.console.C.Yellow + session.console.C.Bold + detail + session.console.C.Reset
		}
		session.console.Write(detail)
	}
	guide := "  ↑/↓: 選択  Enter/→: 決定"
	if toggles != nil {
		guide = "  ↑/↓: 選択  Space/Enter/→: 切替・決定"
	}
	if nested {
		guide += "  b: 1つ戻る  q: 終了"
	} else {
		guide += "  q: 終了"
	}
	if rootMenu {
		session.console.Write(guide)
	} else {
		session.console.Write("\n" + guide)
	}
	return nil
}

func (session *wizardSession) promptValue(title, label, current, hint string) (string, bool, error) {
	if err := session.screen.cursor(true); err != nil {
		return "", false, err
	}
	if err := session.screen.clear(); err != nil {
		return "", false, err
	}
	session.console.Header("未接続")
	session.console.Chapter(title)
	if session.notice != "" {
		session.console.Write("  ▲ " + console.MaskSecrets(session.notice, true))
		session.notice = ""
	}
	session.renderValuePromptTable(label, current, hint)
	session.console.Write()
	session.console.Write("  入力（Enterで確定）")
	fmt.Fprint(session.streams.Out, "    > ")
	line, err := readWizardLine(session.reader, session.streams.In, session.streams.Out)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false, err
	}
	line = strings.TrimSpace(line)
	if strings.EqualFold(line, "b") {
		return "", true, nil
	}
	if errors.Is(err, io.EOF) && line == "" {
		return "", true, nil
	}
	return line, false, nil
}

func (session *wizardSession) renderValuePromptTable(label, current, hint string) {
	type tableRow struct {
		label string
		value string
		bold  bool
	}

	rows := []tableRow{
		{label: "設定項目", value: console.MaskSecrets(label, session.config.Mask), bold: true},
	}
	if hint != "" {
		rows = append(rows, tableRow{label: "説明", value: console.MaskSecrets(hint, session.config.Mask)})
	}
	rows = append(rows,
		tableRow{label: "現在値", value: emptyLabel(console.MaskSecrets(current, session.config.Mask)), bold: true},
		tableRow{label: "入力値", value: "Enterで確定したときの動作", bold: true},
		tableRow{label: "空欄", value: "変更しない"},
		tableRow{label: "-", value: "組み込み既定値に戻す"},
		tableRow{label: "b", value: "1つ前へ戻る"},
	)

	leftWidth := 0
	for _, row := range rows {
		leftWidth = max(leftWidth, console.DisplayWidth(row.label))
	}
	// 罫線・左右余白・インデントを差し引き、端末による意図しない
	// 折返しが起きない幅に収める。インデントは2桁に抑えて説明欄を広く取る。
	const (
		indent     = "  "
		fixedWidth = 9
	)
	rightWidth := max(20, session.console.Width()-fixedWidth-leftWidth)
	line := func(left, middle, right string) string {
		return indent + left + strings.Repeat("─", leftWidth+2) + middle + strings.Repeat("─", rightWidth+2) + right
	}
	border := func(value string) string {
		return session.console.C.Cyan + value + session.console.C.Reset
	}
	writeRow := func(row tableRow) {
		valueLines := wrapPromptCell(row.value, rightWidth)
		for index, value := range valueLines {
			rowLabel := ""
			if index == 0 {
				rowLabel = row.label
			}
			leftPadding := strings.Repeat(" ", leftWidth-console.DisplayWidth(rowLabel))
			rightPadding := strings.Repeat(" ", rightWidth-console.DisplayWidth(value))
			styledLabel := session.console.C.Cyan + session.console.C.Bold + rowLabel + session.console.C.Reset
			styledValue := value
			if row.bold {
				styledValue = session.console.C.Bold + value + session.console.C.Reset
			}
			session.console.Write(indent + "│ " + styledLabel + leftPadding + " │ " + styledValue + rightPadding + " │")
		}
	}

	session.console.Write(border(line("┌", "┬", "┐")))
	operationStart := len(rows) - 4
	for index, row := range rows {
		if index == operationStart {
			session.console.Write(border(line("├", "┼", "┤")))
		}
		writeRow(row)
		if index == operationStart {
			session.console.Write(border(line("├", "┼", "┤")))
		}
	}
	session.console.Write(border(line("└", "┴", "┘")))
}

func wrapPromptCell(value string, width int) []string {
	if width <= 0 {
		return []string{""}
	}
	result := make([]string, 0, 1)
	for _, sourceLine := range strings.Split(value, "\n") {
		if sourceLine == "" {
			result = append(result, "")
			continue
		}
		var line strings.Builder
		lineWidth := 0
		for _, runeValue := range sourceLine {
			runeWidth := max(1, console.DisplayWidth(string(runeValue)))
			if lineWidth > 0 && lineWidth+runeWidth > width {
				result = append(result, line.String())
				line.Reset()
				lineWidth = 0
			}
			line.WriteRune(runeValue)
			lineWidth += runeWidth
		}
		result = append(result, line.String())
	}
	if len(result) == 0 {
		return []string{""}
	}
	return result
}

func readWizardLine(reader *bufio.Reader, input io.Reader, output io.Writer) (string, error) {
	file, terminalInput := input.(*os.File)
	fileDescriptor := -1
	if terminalInput {
		fileDescriptor = int(file.Fd()) // #nosec G115 -- canonical x/term descriptor conversion.
		terminalInput = term.IsTerminal(fileDescriptor)
	}
	if !terminalInput {
		return reader.ReadString('\n')
	}
	state, err := term.MakeRaw(fileDescriptor)
	if err != nil {
		return "", fmt.Errorf("文字入力を開始できません: %w", err)
	}
	restored := false
	restore := func() error {
		if restored {
			return nil
		}
		restored = true
		return term.Restore(fileDescriptor, state)
	}
	defer func() { _ = restore() }()
	value := make([]byte, 0, 64)
	for {
		character, err := reader.ReadByte()
		if err != nil {
			if restoreErr := restore(); restoreErr != nil {
				return "", fmt.Errorf("端末入力を復元できません: %w", restoreErr)
			}
			return string(value), err
		}
		switch character {
		case '\r', '\n':
			_, _ = io.WriteString(output, "\r\n")
			if err := restore(); err != nil {
				return "", fmt.Errorf("端末入力を復元できません: %w", err)
			}
			return string(value), nil
		case 0x03:
			if err := restore(); err != nil {
				return "", fmt.Errorf("端末入力を復元できません: %w", err)
			}
			return "", ErrInteractiveInterrupted
		case 0x04:
			if len(value) == 0 {
				if err := restore(); err != nil {
					return "", fmt.Errorf("端末入力を復元できません: %w", err)
				}
				return "", io.EOF
			}
		case 0x08, 0x7f:
			if len(value) == 0 {
				continue
			}
			runeValue, size := utf8.DecodeLastRune(value)
			if runeValue == utf8.RuneError && size == 1 {
				size = 1
			}
			value = value[:len(value)-size]
			for range max(1, console.DisplayWidth(string(runeValue))) {
				_, _ = io.WriteString(output, "\b \b")
			}
		case 0x15: // Ctrl-U
			for len(value) > 0 {
				runeValue, size := utf8.DecodeLastRune(value)
				value = value[:len(value)-size]
				for range max(1, console.DisplayWidth(string(runeValue))) {
					_, _ = io.WriteString(output, "\b \b")
				}
			}
		case 0x1b:
			// 矢印キーやマウスホイールは ESC で始まる制御シーケンスを
			// 送る。ESC だけを捨てると残りの "[A" や "[<64;...M" が
			// 設定値へ混入するため、終端文字までまとめて読み捨てる。
			if err := discardWizardEscapeSequence(reader); err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
		default:
			if character < 0x20 {
				continue
			}
			value = append(value, character)
			_, _ = output.Write([]byte{character})
		}
	}
}

func discardWizardEscapeSequence(reader *bufio.Reader) error {
	prefix, err := reader.ReadByte()
	if err != nil {
		return err
	}
	switch prefix {
	case '[', 'O': // CSI / SS3: 最終バイトは 0x40〜0x7e。
		parameters, value, found, readErr := scanEscapeParameters(reader, 128)
		if readErr != nil {
			return readErr
		}
		if found {
			// 古いX10マウス形式は ESC [ M の後ろにボタン・X・Yの
			// 3バイトを続ける。ここまで捨てないと座標が文字になる。
			if prefix == '[' && len(parameters) == 0 && value == 'M' {
				for range 3 {
					if _, readErr = reader.ReadByte(); readErr != nil {
						return readErr
					}
				}
			}
			return nil
		}
	case ']': // OSC: BEL または ST (ESC \\) まで。
		escape := false
		for range 1024 {
			value, readErr := reader.ReadByte()
			if readErr != nil {
				return readErr
			}
			if value == '\a' || escape && value == '\\' {
				return nil
			}
			escape = value == 0x1b
		}
	}
	return nil
}

func emptyLabel(value string) string {
	if value == "" {
		return "(未設定)"
	}
	return value
}

func (session *wizardSession) editSettings(base config.Config) (config.Config, string, bool, error) {
	candidate := base
	lastSaved := ""
	sections := settingSections()
	for {
		items := make([]wizardItem, 0, len(sections))
		for _, section := range sections {
			items = append(items, wizardItem{settingSectionLabel(section), settingSectionDescription(section)})
		}
		session.setConfig(candidate)
		choice, back, err := session.choose(
			"設定を変更する",
			"カテゴリを選ぶと、関係する設定だけを表示します。\n各設定はEnterで確定した時点でINIへ自動保存されます。",
			items,
			true,
		)
		if err != nil {
			return base, "", false, err
		}
		if back {
			return candidate, lastSaved, false, nil
		}
		updated, saved, err := session.editSettingsSection(candidate, sections[choice])
		if err != nil {
			return base, "", false, err
		}
		candidate = updated
		if saved != "" {
			lastSaved = saved
		}
	}
}

func (session *wizardSession) editSettingsSection(cfg config.Config, section string) (config.Config, string, error) {
	lastSaved := ""
	for {
		specs := settingsForSection(section)
		items := make([]wizardItem, 0, len(specs))
		for _, spec := range specs {
			items = append(items, wizardItem{spec.Label + ": " + config.SettingSummary(cfg, spec), spec.Description})
		}
		session.setConfig(cfg)
		choice, back, err := session.choose(
			settingSectionLabel(section),
			"変更する設定を選びます。\n値をEnterで確定すると、検証後すぐにINIへ保存されます。",
			items,
			true,
		)
		if err != nil {
			return cfg, lastSaved, err
		}
		if back {
			return cfg, lastSaved, nil
		}
		spec := specs[choice]
		var value string
		var canceled bool
		if spec.Boolean {
			value, canceled, err = session.promptBooleanValue(cfg, spec)
		} else {
			value, canceled, err = session.promptValue(spec.Label, spec.Name, config.SettingSummary(cfg, spec), spec.Description)
		}
		if err != nil {
			return cfg, lastSaved, err
		}
		if canceled || value == "" {
			continue
		}
		updated, saved, err := persistPromptedSetting(cfg, spec, value)
		if err != nil {
			session.notice = err.Error()
			continue
		}
		cfg = updated
		lastSaved = saved
		session.notice = fmt.Sprintf("%sを「%s」へ変更し、設定を保存しました: %s", spec.Label, config.SettingSummary(cfg, spec), saved)
	}
}

func (session *wizardSession) promptBooleanValue(cfg config.Config, spec config.SettingSpec) (string, bool, error) {
	items := []wizardItem{
		{"有効にする (true)", "この機能を有効にしてINIへ保存します"},
		{"無効にする (false)", "この機能を無効にしてINIへ保存します"},
		{"組み込み既定値に戻す", "INIの明示値を削除し、組み込み既定値を使用します"},
	}
	initial := 2
	if cfg.SettingExplicit(spec.Name) {
		initial = 1
		if strings.EqualFold(cfg.SettingValue(spec.Name), "true") {
			initial = 0
		}
	}
	description := strings.Join([]string{
		spec.Description,
		"設定キー: " + spec.Name,
		"現在値: " + config.SettingSummary(cfg, spec),
		"Enterで選択内容を保存します。bで1つ前へ戻ります。",
	}, "\n")
	choice, back, err := session.chooseAt(spec.Label, description, items, true, initial)
	if err != nil || back {
		return "", back, err
	}
	return []string{"true", "false", "-"}[choice], false, nil
}

func persistPromptedSetting(cfg config.Config, spec config.SettingSpec, value string) (config.Config, string, error) {
	updated, err := applyPromptedSetting(cfg, spec.Name, value)
	if err != nil {
		return cfg, "", err
	}
	saved, err := config.SaveINI(updated.ConfigFile, updated)
	if err != nil {
		return cfg, "", err
	}
	updated.ConfigFile = saved
	return updated, saved, nil
}

func settingSections() []string {
	seen := map[string]bool{}
	sections := []string{}
	for _, spec := range config.SettingCatalog() {
		if !seen[spec.Section] {
			seen[spec.Section] = true
			sections = append(sections, spec.Section)
		}
	}
	return sections
}

func settingsForSection(section string) []config.SettingSpec {
	result := []config.SettingSpec{}
	for _, spec := range config.SettingCatalog() {
		if spec.Section == section {
			result = append(result, spec)
		}
	}
	return result
}

func settingSectionLabel(section string) string {
	labels := map[string]string{
		"target": "対象・API", "diagnosis": "診断", "connection": "接続確認",
		"debug": "debug", "display": "表示", "report": "レポート・CI",
		"history": "履歴", "notification": "通知",
	}
	if label := labels[section]; label != "" {
		return label
	}
	return section
}

func settingSectionDescription(section string) string {
	descriptions := map[string]string{
		"target": "Namespace・context・API取得性能", "diagnosis": "モード・ログ・閾値・watch",
		"connection": "Pod個別のProbe/TCP確認", "debug": "kubectl debugのimage/profile",
		"display": "ログ行数・マスク・確認コマンド", "report": "形式・snapshot・diff・CI条件",
		"history": "SQLite履歴とフラッピング判定", "notification": "Webhook通知",
	}
	return descriptions[section]
}
