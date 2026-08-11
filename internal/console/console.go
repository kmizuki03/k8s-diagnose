// Package console renders width-aware, masked terminal output.
package console

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	"github.com/kmizuki03/k8s-diagnose/internal/redact"
	"golang.org/x/term"
)

type Palette struct {
	Red, Yellow, Green, Lime, Blue, Cyan, Magenta, Bold, Dim, Reverse, Reset string
}

type Console struct {
	Out    io.Writer
	Err    io.Writer
	Config config.Config
	C      Palette
	width  int
}

func New(cfg config.Config, out, errOut io.Writer) *Console {
	enabled := os.Getenv("NO_COLOR") == ""
	fd := -1
	if file, ok := out.(*os.File); ok {
		// os.File.Fd is uintptr for API compatibility, while x/term accepts the
		// platform's int file descriptor.
		fd = int(file.Fd()) // #nosec G115 -- canonical x/term descriptor conversion.
		enabled = enabled && term.IsTerminal(fd)
	} else {
		enabled = false
	}
	p := Palette{}
	if enabled {
		p = Palette{Red: "\x1b[0;31m", Yellow: "\x1b[0;33m", Green: "\x1b[0;32m", Lime: "\x1b[38;5;154m", Blue: "\x1b[0;34m", Cyan: "\x1b[0;36m", Magenta: "\x1b[0;35m", Bold: "\x1b[1m", Dim: "\x1b[2m", Reverse: "\x1b[7m", Reset: "\x1b[0m"}
	}
	width := 68
	if fd >= 0 && term.IsTerminal(fd) {
		if terminalWidth, _, err := term.GetSize(fd); err == nil && terminalWidth > 0 {
			width = min(120, max(56, terminalWidth-2))
		}
	}
	return &Console{Out: out, Err: errOut, Config: cfg, C: p, width: width}
}

func (c *Console) ColorEnabled() bool { return c.C.Reset != "" }

// Width returns the display width available to render one terminal line.
func (c *Console) Width() int { return c.width }

func (c *Console) Write(values ...any) {
	if len(values) == 0 {
		fmt.Fprintln(c.Out)
		return
	}
	fmt.Fprintln(c.Out, values...)
}

func (c *Console) Header(context string) {
	inner := max(54, min(c.width-2, 98))
	line := strings.Repeat("═", inner)
	c.printColor(c.C.Blue+c.C.Bold, "╔"+line+"╗")
	title := center(fmt.Sprintf("k8s-diagnose  %s", time.Now().Format("2006-01-02 15:04:05")), inner)
	c.printColor(c.C.Blue+c.C.Bold, "║"+title+"║")
	c.printColor(c.C.Blue+c.C.Bold, "╠"+line+"╣")
	labels := []string{"接続先", "namespace", "モード"}
	values := []string{redact.SanitizeText(context), redact.SanitizeText(c.Config.ScopeLabel()), redact.SanitizeText(modeLabel(c.Config.Mode))}
	labelWidth := 0
	for _, label := range labels {
		labelWidth = max(labelWidth, DisplayWidth(label))
	}
	for index := range labels {
		prefix := "  " + labels[index] + strings.Repeat(" ", labelWidth-DisplayWidth(labels[index])) + " : "
		content := prefix + values[index]
		padding := max(0, inner-DisplayWidth(content))
		if c.ColorEnabled() {
			fmt.Fprintf(c.Out, "%s%s║%s%s%s%s : %s%s%s%s%s║%s\n",
				c.C.Blue, c.C.Bold, c.C.Reset,
				c.C.Blue+c.C.Bold, "  "+labels[index]+strings.Repeat(" ", labelWidth-DisplayWidth(labels[index])), c.C.Reset,
				c.C.Bold, values[index], c.C.Reset, strings.Repeat(" ", padding), c.C.Blue+c.C.Bold, c.C.Reset)
		} else {
			fmt.Fprintf(c.Out, "║%s%s║\n", content, strings.Repeat(" ", padding))
		}
	}
	c.printColor(c.C.Blue+c.C.Bold, "╚"+line+"╝")
	c.Write()
}

func modeLabel(mode string) string {
	switch mode {
	case "all":
		return "all (-a)"
	case "select":
		return "select (-s)"
	case "list":
		return "list (--list)"
	case "triage":
		return "triage"
	case "guide":
		return "ガイド"
	default:
		return mode
	}
}

func (c *Console) Chapter(title string) {
	c.Write()
	c.printColor(c.C.Lime+c.C.Bold, "══════════ "+redact.SanitizeText(title)+" ══════════")
}

func (c *Console) Section(title string, accent ...string) {
	color := c.C.Blue
	if len(accent) > 0 && accent[0] != "" {
		color = accent[0]
	}
	c.Write()
	c.printColor(color+c.C.Bold, "▎"+redact.SanitizeText(title))
	c.printColor(color, strings.Repeat("─", min(c.width, 72)))
}

func (c *Console) Command(command string) {
	if c.Config.ShowCmd {
		c.printColor(c.C.Dim, "    $ "+MaskSecrets(command, c.Config.Mask))
	}
}

func (c *Console) Flag(f model.Finding) {
	icon, color := "?", c.C.Yellow
	switch f.Severity {
	case model.Issue:
		icon, color = "✘", c.C.Red
	case model.Warning:
		icon, color = "▲", c.C.Yellow
	case model.Candidate:
		icon, color = "◇", c.C.Magenta
	}
	ack := ""
	if f.Acknowledged {
		ack = " [承認済み]"
	}
	c.printColor(color, fmt.Sprintf("  %s [%s] %s%s", icon, MaskSecrets(f.Section, c.Config.Mask), MaskSecrets(f.Message, c.Config.Mask), ack))
}

type TableRow struct {
	Cells    []string
	Status   string
	Selected bool
}

// DiagnosticItem is the text-rendering view of one diagnostic check. The app
// layer resolves findings and equivalent kubectl commands so the console does
// not need to know about rule metadata or Kubernetes collection keys.
type DiagnosticItem struct {
	Check        model.Check
	Findings     []model.Finding
	Commands     []string
	Supplemental bool
}

func (c *Console) Table(headers []string, rows []TableRow, colorize bool) {
	if len(rows) == 0 {
		return
	}
	headers = append([]string{}, headers...)
	widths := make([]int, len(headers))
	for i := range headers {
		headers[i] = redact.SanitizeText(headers[i])
		widths[i] = DisplayWidth(headers[i])
	}
	for _, row := range rows {
		for i, value := range row.Cells {
			if i < len(widths) {
				value = MaskSecrets(value, c.Config.Mask)
				widths[i] = max(widths[i], DisplayWidth(value))
			}
		}
	}
	format := func(cells []string) string {
		parts := make([]string, len(headers))
		for index := range headers {
			value := ""
			if index < len(cells) {
				value = MaskSecrets(cells[index], c.Config.Mask)
			}
			parts[index] = value + strings.Repeat(" ", max(0, widths[index]-DisplayWidth(value)))
		}
		return strings.TrimRight(strings.Join(parts, "  "), " ")
	}
	c.printColor(c.C.Bold, format(headers))
	for index, row := range rows {
		color := ""
		if colorize {
			color = c.rowColor(index, row.Status+" "+strings.Join(row.Cells, " "))
		}
		if row.Selected {
			// Some base colours intentionally include an ANSI reset. Apply the
			// selection attributes last so either zebra colour remains selected.
			color += c.C.Reverse + c.C.Bold
		}
		c.printColor(color, format(row.Cells))
	}
}

func (c *Console) PodTable(headers []string, rows []TableRow) {
	if c.ColorEnabled() {
		fmt.Fprintf(c.Out, "  %s■ 異常%s  %s■ 待機・要注意%s  %s■%s■ 正常（ゼブラ表示）%s\n", c.C.Red, c.C.Reset, c.C.Yellow, c.C.Reset, c.C.Green, c.C.Lime, c.C.Reset)
	}
	if len(rows) == 0 {
		c.printColor(c.C.Green, "（Podなし）")
		return
	}
	headers = append([]string{}, headers...)
	widths := make([]int, len(headers))
	for i := range headers {
		headers[i] = redact.SanitizeText(headers[i])
		widths[i] = DisplayWidth(headers[i])
	}
	for _, row := range rows {
		for i, value := range row.Cells {
			if i < len(widths) {
				value = MaskSecrets(value, c.Config.Mask)
				widths[i] = max(widths[i], DisplayWidth(value))
			}
		}
	}
	line := func(cells []string) string {
		parts := make([]string, len(headers))
		for i := range headers {
			value := ""
			if i < len(cells) {
				value = MaskSecrets(cells[i], c.Config.Mask)
			}
			parts[i] = value + strings.Repeat(" ", max(0, widths[i]-DisplayWidth(value)))
		}
		return strings.TrimRight(strings.Join(parts, "  "), " ")
	}
	c.printColor(c.C.Cyan+c.C.Bold, line(headers))
	for index, row := range rows {
		style := c.rowColor(index, row.Status)
		if row.Selected {
			style += c.C.Reverse + c.C.Bold
		}
		c.printColor(style, line(row.Cells))
	}
}

// DiagnosticContents shows what each enabled rule inspected, the equivalent
// kubectl command, and the result attributed to that rule. An available check
// means that the rule had enough input to run; abnormalities are determined by
// the findings attached to the item.
func (c *Console) DiagnosticContents(items []DiagnosticItem) {
	if len(items) == 0 {
		return
	}
	values := append([]DiagnosticItem{}, items...)
	sort.SliceStable(values, func(i, j int) bool {
		leftSection, rightSection := strings.TrimSpace(values[i].Check.Section), strings.TrimSpace(values[j].Check.Section)
		if leftSection != rightSection {
			return leftSection < rightSection
		}
		leftDescription, rightDescription := strings.TrimSpace(values[i].Check.Description), strings.TrimSpace(values[j].Check.Description)
		if leftDescription != rightDescription {
			return leftDescription < rightDescription
		}
		return values[i].Check.ID < values[j].Check.ID
	})

	available, unavailable := 0, 0
	for _, item := range values {
		if item.Check.Available {
			available++
		} else {
			unavailable++
		}
	}

	c.Section("診断内容（実施状況）", c.C.Cyan)
	if c.ColorEnabled() {
		fmt.Fprintf(c.Out, "  実施状況: %s✔ 実施済み %d件%s / %s? 確認不能 %d件%s\n",
			c.C.Green+c.C.Bold, available, c.C.Reset, c.C.Yellow+c.C.Bold, unavailable, c.C.Reset)
	} else {
		c.Write(fmt.Sprintf("  実施状況: ✔ 実施済み %d件 / ? 確認不能 %d件", available, unavailable))
	}
	c.printWrapped(c.C.Dim, "  ※ ", "各項目の確認コマンドを結果の前に表示します。実施済みは正常という意味ではなく、判定を実行できたことを表します")

	currentSection := ""
	availableIndex := 0
	for _, item := range values {
		check := item.Check
		section := strings.TrimSpace(check.Section)
		if section == "" {
			section = "その他"
		}
		if section != currentSection {
			if currentSection == "" {
				c.Write()
			}
			c.printColor(c.C.Cyan+c.C.Bold, "  "+MaskSecrets(section, c.Config.Mask))
			currentSection = section
		}

		description := strings.TrimSpace(check.Description)
		if description == "" {
			description = strings.TrimSpace(check.ID)
		}
		if description == "" {
			description = "検査内容が設定されていません"
		}
		descriptionColor := c.C.Yellow
		if check.Available {
			descriptionColor = c.C.Green
			if availableIndex%2 == 1 {
				descriptionColor = c.C.Lime
			}
			availableIndex++
		}
		c.printWrapped(descriptionColor, "    検査: ", description)
		if c.Config.ShowCmd {
			for _, command := range item.Commands {
				c.printWrapped(c.C.Dim, "      $ ", command)
			}
		}

		result, resultColor := c.diagnosticResult(item)
		c.printWrapped(resultColor+c.C.Bold, "    結果: ", result)
		if !check.Available {
			reason := strings.TrimSpace(check.Reason)
			if reason == "" {
				reason = "判定に必要な情報を取得できませんでした"
			}
			c.printWrapped(c.C.Yellow, "      └─ 理由: ", reason)
			continue
		}
		c.renderDiagnosticFindings(item.Findings)
	}
}

func (c *Console) diagnosticResult(item DiagnosticItem) (string, string) {
	if !item.Check.Available {
		return "? 確認不能", c.C.Yellow
	}
	if item.Supplemental {
		return "✔ 追加情報を取得済み", c.C.Green
	}
	counts := map[model.Severity]int{}
	acknowledged := 0
	for _, finding := range item.Findings {
		counts[finding.Severity]++
		if finding.Acknowledged {
			acknowledged++
		}
	}
	parts := []string{}
	color := c.C.Green
	for _, value := range []struct {
		severity model.Severity
		label    string
		style    string
	}{
		{model.Issue, "✘ 確定異常", c.C.Red},
		{model.Warning, "▲ 警告", c.C.Yellow},
		{model.Unavailable, "? 確認不能", c.C.Yellow},
		{model.Candidate, "◇ 要確認", c.C.Magenta},
	} {
		if count := counts[value.severity]; count > 0 {
			parts = append(parts, fmt.Sprintf("%s %d件", value.label, count))
			if len(parts) == 1 {
				color = value.style
			}
		}
	}
	if len(parts) == 0 {
		return "✔ 所見なし", c.C.Green
	}
	result := strings.Join(parts, " / ")
	if acknowledged > 0 {
		result += fmt.Sprintf("（承認済み %d件）", acknowledged)
	}
	return result, color
}

func (c *Console) renderDiagnosticFindings(findings []model.Finding) {
	if len(findings) == 0 {
		return
	}
	values := append([]model.Finding{}, findings...)
	sort.SliceStable(values, func(i, j int) bool {
		left, right := diagnosticSeverityRank(values[i].Severity), diagnosticSeverityRank(values[j].Severity)
		if left != right {
			return left < right
		}
		return values[i].Message < values[j].Message
	})
	for index, finding := range values {
		branch := "├─"
		if index == len(values)-1 {
			branch = "└─"
		}
		icon, label, color := "◇", "要確認", c.C.Magenta
		switch finding.Severity {
		case model.Issue:
			icon, label, color = "✘", "確定異常", c.C.Red
		case model.Warning:
			icon, label, color = "▲", "警告", c.C.Yellow
		case model.Unavailable:
			icon, label, color = "?", "確認不能", c.C.Yellow
		}
		acknowledged := ""
		if finding.Acknowledged {
			acknowledged = " [承認済み]"
		}
		c.printWrapped(color, "      "+branch+" "+icon+" ", "["+label+"] "+finding.Message+acknowledged)
	}
}

func diagnosticSeverityRank(severity model.Severity) int {
	switch severity {
	case model.Issue:
		return 0
	case model.Warning:
		return 1
	case model.Unavailable:
		return 2
	default:
		return 3
	}
}

func (c *Console) printWrapped(color, prefix, value string) {
	prefix = redact.SanitizeText(prefix)
	value = MaskSecrets(value, c.Config.Mask)
	lineWidth := c.width
	if lineWidth <= 0 {
		lineWidth = 68
	}
	lines := wrapDisplay(value, max(12, lineWidth-DisplayWidth(prefix)))
	if len(lines) == 0 {
		lines = []string{"（内容なし）"}
	}
	continuation := strings.Repeat(" ", DisplayWidth(prefix))
	for index, line := range lines {
		linePrefix := prefix
		if index > 0 {
			linePrefix = continuation
		}
		c.printColor(color, linePrefix+line)
	}
}

func wrapDisplay(value string, limit int) []string {
	value = strings.TrimSpace(strings.Join(strings.Fields(redact.SanitizeText(value)), " "))
	if value == "" {
		return nil
	}
	limit = max(1, limit)
	lines := []string{}
	var line strings.Builder
	width := 0
	flush := func() {
		if line.Len() == 0 {
			return
		}
		if value := strings.TrimRight(line.String(), " "); value != "" {
			lines = append(lines, value)
		}
		line.Reset()
		width = 0
	}
	appendToken := func(token string) {
		tokenWidth := DisplayWidth(token)
		if token == " " && width == 0 {
			return
		}
		if tokenWidth <= limit {
			if width > 0 && width+tokenWidth > limit {
				flush()
			}
			if token == " " && width == 0 {
				return
			}
			line.WriteString(token)
			width += tokenWidth
			return
		}
		// Exceptionally long URLs and identifiers cannot move to a fresh line as
		// one unit. Split only those tokens at display-rune boundaries.
		if width > 0 {
			flush()
		}
		for _, r := range token {
			runeWidth := DisplayWidth(string(r))
			if width > 0 && width+runeWidth > limit {
				flush()
			}
			line.WriteRune(r)
			width += runeWidth
		}
	}

	runes := []rune(value)
	for index := 0; index < len(runes); {
		start := index
		// Keep Latin identifiers such as targetPort and Endpoint intact. A
		// Japanese middle dot immediately before one belongs to the same token,
		// avoiding an orphaned separator at the end of the previous line.
		if runes[index] == '・' && index+1 < len(runes) && isWrapIdentifierRune(runes[index+1]) {
			index++
			for index < len(runes) && isWrapIdentifierRune(runes[index]) {
				index++
			}
			appendToken(string(runes[start:index]))
			continue
		}
		if isWrapIdentifierRune(runes[index]) {
			for index < len(runes) && isWrapIdentifierRune(runes[index]) {
				index++
			}
			appendToken(string(runes[start:index]))
			continue
		}
		index++
		appendToken(string(runes[start:index]))
	}
	flush()
	return lines
}

func isWrapIdentifierRune(r rune) bool {
	if r > unicode.MaxASCII {
		return false
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("_./:@%+-=", r)
}

var errorRow = regexp.MustCompile(`(?i)CrashLoopBackOff|ImagePullBackOff|ErrImagePull|CreateContainerConfigError|RunContainerError|InvalidImageName|CreateContainerError|OOMKilled|Error|Failed|Evicted|Lost|NotReady|Unknown`)
var warningRow = regexp.MustCompile(`(?i)Pending|ContainerCreating|PodInitializing|Terminating|Init:|Completed|Succeeded|Not-Ready`)

func (c *Console) rowColor(index int, text string) string {
	if errorRow.MatchString(text) {
		return c.C.Red
	}
	if warningRow.MatchString(text) {
		return c.C.Yellow
	}
	if index%2 == 0 {
		return c.C.Green
	}
	return c.C.Lime
}

func (c *Console) RootCauseReport(values []model.RootCause) {
	if len(values) == 0 {
		return
	}
	c.Section("根本原因分析", c.C.Magenta)
	confirmed, probable, related := 0, 0, 0
	for _, root := range values {
		switch root.Classification {
		case "root_cause":
			confirmed++
		case "cause_candidate":
			probable++
		default:
			related++
		}
	}
	if c.ColorEnabled() {
		fmt.Fprintf(c.Out, "%s原因分析: %s%s根本原因 %d件%s / %s%s原因候補 %d件%s / %s%s要確認 %d件%s\n",
			c.C.Bold, c.C.Reset, c.C.Red+c.C.Bold, confirmed, c.C.Reset,
			c.C.Yellow, c.C.Bold, probable, c.C.Reset, c.C.Magenta, c.C.Bold, related, c.C.Reset)
	} else {
		fmt.Fprintf(c.Out, "原因分析: 根本原因 %d件 / 原因候補 %d件 / 要確認 %d件\n", confirmed, probable, related)
	}
	for index, root := range values {
		icon, color := rootStyle(c, root)
		c.Write()
		c.printColor(color+c.C.Bold, fmt.Sprintf("[%d] %s %s", index+1, icon, root.Label))
		c.printColor(color, "    "+MaskSecrets(root.Cause.Message, c.Config.Mask))
		for _, evidence := range root.Evidence {
			if evidence.Kind == "decision" && strings.TrimSpace(evidence.Value) != "" {
				c.printColor(c.C.Cyan, "    検出理由: "+MaskSecrets(evidence.Value, c.Config.Mask))
				break
			}
		}
		counts := []string{}
		keys := make([]string, 0, len(root.ImpactSummary))
		for key := range root.ImpactSummary {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			counts = append(counts, fmt.Sprintf("%s %d", key, root.ImpactSummary[key]))
		}
		if len(counts) > 0 {
			fmt.Fprintf(c.Out, "    %s影響:%s %s\n", c.C.Cyan, c.C.Reset, strings.Join(counts, " / "))
		}
	}
	for index, root := range values {
		icon, color := rootStyle(c, root)
		c.Section(fmt.Sprintf("%s %s [%d]", icon, root.Label, index+1), color)
		if c.Config.ShowCmd {
			for _, command := range root.Commands {
				c.Command(command)
			}
		}
		c.printColor(color+c.C.Bold, fmt.Sprintf("%s %s [確信度: %d%%]", icon, root.Label, root.Confidence))
		c.printColor(color+c.C.Bold, MaskSecrets(root.Cause.Message, c.Config.Mask))
		reasons := []string{}
		if root.Cause.Code != "" {
			reasons = append(reasons, "判定ルール: "+root.Cause.Code)
		}
		if root.Cause.Resource != "" {
			reasons = append(reasons, "対象リソース: "+root.Cause.Resource)
		}
		for _, evidence := range root.Evidence {
			label := rootCauseEvidenceLabel(evidence)
			value := evidence.Value
			if label != "" {
				value = label + ": " + value
			}
			reasons = append(reasons, value)
		}
		if len(reasons) > 0 {
			c.Write()
			c.printColor(c.C.Cyan+c.C.Bold, "検出理由・根拠")
			for i, reason := range reasons {
				branch := "├─"
				if i == len(reasons)-1 {
					branch = "└─"
				}
				c.Write(branch + " " + MaskSecrets(reason, c.Config.Mask))
			}
		}
		impacts := append(append([]model.Impact{}, root.DirectImpacts...), root.PropagatedImpacts...)
		if len(impacts) > 0 {
			c.Write()
			c.printColor(c.C.Magenta+c.C.Bold, "影響経路（直接影響 → 波及影響）")
			c.renderImpactTree(impacts, color)
		}
		if len(root.Remediations) > 0 {
			c.Write()
			c.printColor(c.C.Lime+c.C.Bold, "◆ 修正候補")
			for _, remediation := range root.Remediations {
				c.printColor(c.C.Lime+c.C.Bold, "  ▶ "+MaskSecrets(remediation, c.Config.Mask))
			}
		}
	}
}

func rootCauseEvidenceLabel(evidence model.Evidence) string {
	key := strings.Trim(strings.TrimSpace(evidence.Kind)+"."+strings.TrimSpace(evidence.Key), ".")
	switch key {
	case "api.errors", "api.reason":
		return "Kubernetes APIのエラー"
	case "container.state":
		return "コンテナの状態"
	case "container.lastTerminationReason":
		return "前回終了した理由"
	case "container.lastExitCode":
		return "前回の終了コード"
	case "container.restartCount":
		return "再起動回数"
	case "pod.phase":
		return "Podの状態（phase）"
	case "pod.deletionTimestamp", "namespace.deletionTimestamp":
		return "削除開始時刻"
	case "pod.nominatedNodeName":
		return "候補として指名されたNode"
	case "status.readyReplicas":
		return "Ready状態のレプリカ数"
	case "status.currentHealthy":
		return "現在正常なPod数"
	case "status.desiredHealthy":
		return "必要な正常Pod数"
	case "status.disruptionsAllowed":
		return "安全に退避（Eviction）できるPod数"
	case "reference.source":
		return "参照元の設定"
	case "reference.pod":
		return "参照しているPod"
	case "reference.secret":
		return "参照先のSecret"
	case "reference.service":
		return "参照先のService"
	case "spec.storageClassName":
		return "指定されたStorageClass"
	case "service.spec.ports":
		return "Serviceポート設定"
	case "service.spec.selector":
		return "Service selector"
	case "service.selectorMatches", "pod.selectorMatches":
		return "selectorに一致したPod"
	case "pod.containerPortNames":
		return "Podに定義されたcontainerPort"
	case "decision.unresolved":
		return "判定"
	case "endpointSlice.resolvedPort":
		return "EndpointSliceの確認結果"
	case "probe.portName":
		return "Probeのポート設定"
	case "container.ports[].name":
		return "containerPortの設定"
	case "endpoint.ready":
		return "Ready状態のEndpoint数"
	case "endpoint.terminatingServing":
		return "終了処理中で通信可能な代替Endpoint数"
	case "event.directEvidence":
		return "FailedScheduling Event"
	case "unknown.constraint":
		return "静的に評価できなかった条件"
	case "lease.renewTime":
		return "Leaseの最終更新時刻"
	case "connect.detail":
		return "接続確認の結果"
	case "connect.sampleCount":
		return "確認回数"
	case "connect.kubeletThresholdEvaluation":
		return "kubeletの連続判定"
	case "http.statusCode":
		return "HTTPステータス"
	case "http.contentType":
		return "HTTP Content-Type"
	case "http.bodyBytesRead":
		return "読み取ったHTTP本文のバイト数"
	case "log.match":
		return "ログで一致した箇所"
	case "x509.error":
		return "証明書の解析エラー"
	case "x509.keyPairError":
		return "証明書と秘密鍵の検証エラー"
	}
	if strings.HasPrefix(key, "condition.") {
		return "状態条件（condition） " + strings.TrimPrefix(key, "condition.")
	}
	if strings.HasPrefix(key, "node.") {
		return "Node " + strings.TrimPrefix(key, "node.") + " の配置不可理由"
	}
	if strings.HasPrefix(key, "scheduling.") {
		return "スケジューリング判定（" + strings.TrimPrefix(key, "scheduling.") + "）"
	}
	if strings.HasPrefix(key, "x509.") {
		return "証明書情報（" + strings.TrimPrefix(key, "x509.") + "）"
	}
	return key
}

func rootStyle(c *Console, root model.RootCause) (string, string) {
	switch root.Classification {
	case "root_cause":
		return "✘", c.C.Red
	case "cause_candidate":
		return "▲", c.C.Yellow
	default:
		return "◇", c.C.Magenta
	}
}

func (c *Console) renderImpactTree(impacts []model.Impact, color string) {
	// Each impact already carries the complete dependency path. Building a trie
	// preserves shared prefixes and shows the actual propagation path once.
	type node struct {
		name, message string
		children      map[string]*node
	}
	tree := &node{children: map[string]*node{}}
	for _, impact := range impacts {
		current := tree
		path := impact.Path
		if len(path) == 0 {
			path = []string{impact.Resource}
		}
		for _, part := range path {
			part = MaskSecrets(part, c.Config.Mask)
			if current.children[part] == nil {
				current.children[part] = &node{name: part, children: map[string]*node{}}
			}
			current = current.children[part]
		}
		if impact.Message != "" {
			current.message = MaskSecrets(impact.Message, c.Config.Mask)
		}
	}
	var walk func(*node, string)
	walk = func(parent *node, prefix string) {
		keys := make([]string, 0, len(parent.children))
		for key := range parent.children {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for i, key := range keys {
			last := i == len(keys)-1
			branch := "├─ "
			next := prefix + "│  "
			if last {
				branch = "└─ "
				next = prefix + "   "
			}
			child := parent.children[key]
			line := prefix + branch + child.name
			if child.message != "" {
				line += " — " + child.message
			}
			if prefix == "" {
				c.printColor(color+c.C.Bold, line)
			} else {
				c.Write(line)
			}
			walk(child, next)
		}
	}
	walk(tree, "")
}

func (c *Console) Summary(state *model.State, beforeFinding ...func(model.Finding)) {
	sections := []struct {
		severity model.Severity
		title    string
		color    string
	}{
		{model.Issue, "確定異常", c.C.Red}, {model.Warning, "警告", c.C.Yellow},
		{model.Unavailable, "確認できなかった項目", c.C.Yellow},
		{model.Candidate, "要確認の候補", c.C.Magenta},
	}
	for _, section := range sections {
		values := state.BySeverity(section.severity, false)
		if len(values) == 0 {
			continue
		}
		c.Section(section.title, section.color)
		for _, finding := range values {
			for _, callback := range beforeFinding {
				if callback != nil {
					callback(finding)
				}
			}
			c.Flag(finding)
		}
		c.Write(fmt.Sprintf("  （%d件）", len(values)))
	}
	scoreTitle := "クラスタ健全性スコア"
	healthDescription := "Health＝クラスタ状態 / Coverage＝診断できた範囲"
	var scopedScore *model.ScopedScore
	if c.Config.Mode == "select" {
		scoreTitle = "Pod総合スコア"
		healthDescription = "総合＝選択Podの12診断項目（状態・依存・通信・TLS等） / Coverage＝確認できた範囲"
		scopedScore = state.ScopedScoreValue()
	}
	c.Section(scoreTitle)
	health, coverage := state.Health(), state.Coverage()
	grade, gradeLabel, healthColor := "A", "良好", c.C.Green
	if health < 90 {
		grade, gradeLabel, healthColor = "B", "注意", c.C.Yellow
	}
	if health < 75 {
		grade, gradeLabel = "C", "要改善"
	}
	if health < 60 {
		grade, gradeLabel, healthColor = "D", "重大", c.C.Red
	}
	barWidth := max(12, min(24, c.width-38))
	healthLabel := "Health:"
	if c.Config.Mode == "select" {
		healthLabel = "総合:"
	}
	healthLabel += strings.Repeat(" ", max(0, 9-DisplayWidth(healthLabel)))
	c.printColor(healthColor+c.C.Bold, fmt.Sprintf("  %s [%s] %3d/100  [%s] %s", healthLabel, scoreBar(health, barWidth), health, grade, gradeLabel))
	if scopedScore != nil && len(scopedScore.Dimensions) > 0 {
		c.printColor(c.C.Bold, "  内訳:")
		labelWidth := 0
		for _, dimension := range scopedScore.Dimensions {
			labelWidth = max(labelWidth, DisplayWidth(dimension.Label))
		}
		dimensionBarWidth := max(6, min(12, barWidth/2))
		for _, dimension := range scopedScore.Dimensions {
			percentage := 100
			if dimension.Maximum > 0 {
				percentage = max(0, min(100, dimension.Score*100/dimension.Maximum))
			}
			color := c.C.Green
			if percentage < 90 {
				color = c.C.Yellow
			}
			if percentage < 60 {
				color = c.C.Red
			}
			label := dimension.Label + strings.Repeat(" ", labelWidth-DisplayWidth(dimension.Label))
			line := fmt.Sprintf("    %s [%s] %2d/%-2d", label, scoreBar(percentage, dimensionBarWidth), dimension.Score, dimension.Maximum)
			if dimension.Detail != "" {
				line += "  " + Snip(dimension.Detail, max(20, c.width-DisplayWidth(line)-2))
			}
			c.printColor(color, line)
		}
	}
	ok, unavailable, total := state.CoverageCounts()
	coverageLabel := "Coverage:"
	coverageLabel += strings.Repeat(" ", max(0, 9-DisplayWidth(coverageLabel)))
	c.printColor(c.C.Cyan+c.C.Bold, fmt.Sprintf("  %s [%s] %3d%%", coverageLabel, scoreBar(coverage, barWidth), coverage))
	coverageDetail := fmt.Sprintf("確認済み %d/%d・確認不能 %d項目", ok, total, unavailable)
	if total == 0 {
		coverageDetail = "確認対象なし"
	}
	c.printColor(c.C.Dim, "            "+coverageDetail)
	issues := len(state.BySeverity(model.Issue, false))
	warnings := len(state.BySeverity(model.Warning, false))
	unavailableFindings := len(state.BySeverity(model.Unavailable, false))
	candidates := len(state.BySeverity(model.Candidate, false))
	if c.ColorEnabled() {
		fmt.Fprintf(c.Out, "  所見:      %s✘ 確定 %d%s   %s▲ 警告 %d%s   %s? 確認不能 %d%s   %s◇ 候補 %d%s\n",
			c.C.Red+c.C.Bold, issues, c.C.Reset,
			c.C.Yellow+c.C.Bold, warnings, c.C.Reset,
			c.C.Yellow, unavailableFindings, c.C.Reset,
			c.C.Magenta, candidates, c.C.Reset)
	} else {
		c.Write(fmt.Sprintf("  所見:      ✘ 確定 %d   ▲ 警告 %d   ? 確認不能 %d   ◇ 候補 %d", issues, warnings, unavailableFindings, candidates))
	}
	c.printColor(c.C.Dim, "  "+healthDescription)
}

func scoreBar(value, width int) string {
	value = max(0, min(100, value))
	width = max(1, width)
	filled := value * width / 100
	if value == 100 {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func (c *Console) printColor(color, value string) {
	if color == "" {
		fmt.Fprintln(c.Out, value)
		return
	}
	fmt.Fprintf(c.Out, "%s%s%s\n", color, value, c.C.Reset)
}

func center(value string, width int) string {
	padding := max(0, width-DisplayWidth(value))
	left := padding / 2
	return strings.Repeat(" ", left) + value + strings.Repeat(" ", padding-left)
}

func DisplayWidth(value string) int {
	value = ansiRE.ReplaceAllString(value, "")
	width := 0
	for _, r := range value {
		if unicode.Is(unicode.Mn, r) || r == '\u200d' {
			continue
		}
		if isWide(r) {
			width += 2
		} else {
			width++
		}
	}
	return width
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func isWide(r rune) bool {
	return r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		(r >= 0xac00 && r <= 0xd7a3) || (r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe10 && r <= 0xfe19) || (r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) || (r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1faff) || (r >= 0x20000 && r <= 0x3fffd))
}

func MaskSecrets(value string, enabled bool) string {
	value = redact.SanitizeText(value)
	if !enabled || value == "" {
		return value
	}
	return redact.MaskSecrets(value)
}

func Snip(value string, limit int) string {
	value = redact.SanitizeText(value)
	value = strings.TrimSpace(strings.Join(strings.Fields(value), " "))
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	runes := []rune(value)
	return string(runes[:max(0, limit-1)]) + "…"
}

// TruncateDisplay shortens a string to at most limit terminal columns. It is
// suitable for menu labels containing Japanese or other wide characters.
func TruncateDisplay(value string, limit int) string {
	value = redact.SanitizeText(value)
	if limit <= 0 {
		return ""
	}
	if DisplayWidth(value) <= limit {
		return value
	}
	if limit == 1 {
		return "…"
	}
	target := limit - DisplayWidth("…")
	var builder strings.Builder
	width := 0
	for _, r := range value {
		runeWidth := DisplayWidth(string(r))
		if width+runeWidth > target {
			break
		}
		builder.WriteRune(r)
		width += runeWidth
	}
	return builder.String() + "…"
}
