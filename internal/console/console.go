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
		fmt.Fprintf(c.Out, "  %s■ 異常%s  %s■ 待機・要注意%s  %s■%s■ 正常 (ゼブラ)%s\n", c.C.Red, c.C.Reset, c.C.Yellow, c.C.Reset, c.C.Green, c.C.Lime, c.C.Reset)
	}
	if len(rows) == 0 {
		c.printColor(c.C.Green, "(Podなし)")
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
			c.printColor(c.C.Magenta+c.C.Bold, "影響経路 (直接影響 → 波及影響)")
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
	case "service.spec.ports":
		return "Serviceポート設定"
	case "service.spec.selector":
		return "Service selector"
	case "service.selectorMatches", "pod.selectorMatches":
		return "selector一致Pod"
	case "pod.containerPortNames":
		return "Pod側のcontainerPort"
	case "decision.unresolved":
		return "判定"
	case "endpointSlice.resolvedPort":
		return "EndpointSlice確認"
	case "probe.portName":
		return "Probeポート設定"
	case "container.ports[].name":
		return "containerPort設定"
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
		c.Write(fmt.Sprintf("  (%d 件)", len(values)))
	}
	c.Section("クラスタ健全性スコア")
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
	c.printColor(healthColor+c.C.Bold, fmt.Sprintf("  Health:   [%s] %3d/100  [%s] %s", scoreBar(health, barWidth), health, grade, gradeLabel))
	ok, unavailable, total := state.CoverageCounts()
	c.printColor(c.C.Cyan+c.C.Bold, fmt.Sprintf("  Coverage: [%s] %3d%%", scoreBar(coverage, barWidth), coverage))
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
	c.printColor(c.C.Dim, "  Health＝クラスタ状態 / Coverage＝診断できた範囲")
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
