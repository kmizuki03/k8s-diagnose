package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"golang.org/x/term"
	corev1 "k8s.io/api/core/v1"
)

// ErrInteractiveInterrupted marks Ctrl-C received while a local selection or
// settings screen owns the terminal.
var ErrInteractiveInterrupted = errors.New("対話操作が中断されました")

var errPodSelectionInterrupted = ErrInteractiveInterrupted

type podSelectionAction uint8

const (
	podSelectionNone podSelectionAction = iota
	podSelectionUp
	podSelectionDown
	podSelectionHome
	podSelectionEnd
	podSelectionPageUp
	podSelectionPageDown
	podSelectionChoose
	podSelectionToggle
	podSelectionResearch
	podSelectionNamespaceSearch
	podSelectionNameSearch
	podSelectionClearSearch
	podSelectionBack
	podSelectionQuit
	podSelectionInterrupt
)

type podSelectionScreen struct {
	output    io.Writer
	alternate bool
	height    int
}

func newPodSelectionScreen(input io.Reader, output io.Writer) *podSelectionScreen {
	screen := &podSelectionScreen{output: output, height: 24}
	inputFile, inputOK := input.(*os.File)
	outputFile, outputOK := output.(*os.File)
	if !inputOK || !outputOK || os.Getenv("TERM") == "dumb" {
		return screen
	}
	inputFD := int(inputFile.Fd())   // #nosec G115 -- canonical x/term descriptor conversion.
	outputFD := int(outputFile.Fd()) // #nosec G115 -- canonical x/term descriptor conversion.
	if !term.IsTerminal(inputFD) || !term.IsTerminal(outputFD) {
		return screen
	}
	screen.alternate = true
	if _, height, err := term.GetSize(outputFD); err == nil && height > 0 {
		screen.height = height
	}
	return screen
}

func (screen *podSelectionScreen) open() error {
	if !screen.alternate {
		return nil
	}
	_, err := io.WriteString(screen.output, "\x1b[?1049h\x1b[2J\x1b[H")
	return err
}

func (screen *podSelectionScreen) close() {
	if screen.alternate {
		_, _ = io.WriteString(screen.output, "\x1b[?25h\x1b[?1049l")
	}
}

func (screen *podSelectionScreen) clear() error {
	if !screen.alternate {
		return nil
	}
	_, err := io.WriteString(screen.output, "\x1b[2J\x1b[H")
	return err
}

func (screen *podSelectionScreen) cursor(visible bool) error {
	if !screen.alternate {
		return nil
	}
	sequence := "\x1b[?25l"
	if visible {
		sequence = "\x1b[?25h"
	}
	_, err := io.WriteString(screen.output, sequence)
	return err
}

func (screen *podSelectionScreen) pageSize(total int, notice bool) int {
	if !screen.alternate {
		return max(1, total)
	}
	// Header、検索条件、chapter、凡例、表ヘッダ、選択中表示、3行の操作
	// ガイドと最終改行を先に確保する。通知がある再描画ではさらに1行を
	// 確保し、最下行への改行で端末全体がスクロールすることを防ぐ。
	reserved := 20
	if notice {
		reserved++
	}
	return min(max(3, screen.height-reserved), max(1, total))
}

func (screen *podSelectionScreen) menuPageSize(total int) int {
	if !screen.alternate {
		return max(1, total)
	}
	// Menus render the selected item's description beneath the list. Reserve
	// enough lines that moving to the fifth item scrolls instead of wrapping
	// into the terminal footer.
	return min(max(3, screen.height-20), max(1, total))
}

func (screen *podSelectionScreen) rootMenuPageSize(total int) int {
	if !screen.alternate {
		return max(1, total)
	}
	// The root guide has only eight entries and uses a compact description and
	// footer layout. Fifteen rows cover the header and fixed text, so a common
	// 23-line terminal can show every entry without scrolling.
	return min(max(3, screen.height-15), max(1, total))
}

func (runner *Runner) promptPod(pods []corev1.Pod) (*corev1.Pod, bool, error) {
	reader := runner.reader
	if reader == nil {
		reader = bufio.NewReader(runner.Streams.In)
		runner.reader = reader
	}
	screen := newPodSelectionScreen(runner.Streams.In, runner.Streams.Out)
	defer screen.close()
	if err := screen.open(); err != nil {
		return nil, false, fmt.Errorf("Pod選択画面を開始できません: %w", err)
	}

	namespaceQuery := ""
	nameQuery := ""
	selected := 0
	notice := ""
	for {
		if err := screen.cursor(false); err != nil {
			return nil, false, err
		}
		if err := screen.clear(); err != nil {
			return nil, false, err
		}
		runner.Console.Header(runner.Clients.Context)
		runner.Console.Chapter("Pod選択")
		namespaceFilter := namespaceQuery
		if runner.Config.Namespace != "" {
			namespaceFilter = runner.Config.Namespace
			line := "  Namespace検索: " + console.MaskSecrets(runner.Config.Namespace, runner.Config.Mask) + " (-nで固定)"
			runner.Console.Write(console.TruncateDisplay(line, runner.Console.Width()))
		} else {
			line := "  Namespace検索: " + podFilterLabel(namespaceQuery, runner.Config.Mask) + "  [nで編集]"
			runner.Console.Write(console.TruncateDisplay(line, runner.Console.Width()))
		}
		nameFilterLine := "  Pod名検索    : " + podFilterLabel(nameQuery, runner.Config.Mask) + "  [/ または f で編集]"
		runner.Console.Write(console.TruncateDisplay(nameFilterLine, runner.Console.Width()))
		hasNotice := notice != ""
		if hasNotice {
			runner.Console.Write(console.TruncateDisplay("  "+notice, runner.Console.Width()))
			notice = ""
		}

		candidates := sortedPods(filterPods(pods, namespaceFilter, nameQuery))
		if len(candidates) > 0 {
			selected = min(selected, len(candidates)-1)
			start, end := selectionWindow(len(candidates), selected, screen.pageSize(len(candidates), hasNotice))
			// 全候補から列幅を一度だけ決めてから表示範囲を切り出す。スクロール
			// のたびに列位置が左右へ揺れることを防ぐ。
			rows := fitSelectionPodRows(selectionPodRows(candidates, selected), runner.Console.Width())
			runner.Console.PodTable(podSelectionHeaders, rows[start:end])
			if start > 0 || end < len(candidates) {
				runner.Console.Write(fmt.Sprintf("  表示 %d-%d / %d件", start+1, end, len(candidates)))
			}
			selectedLabel := fmt.Sprintf("  選択中: %s/%s", candidates[selected].Namespace, candidates[selected].Name)
			runner.Console.Write(console.TruncateDisplay(selectedLabel, runner.Console.Width()))
		} else {
			selected = 0
			runner.Console.PodTable(podSelectionHeaders, nil)
			runner.Console.Write("  ▲ 一致するPodがありません。")
			runner.Console.Write("    n または / で検索条件を変更してください。")
		}
		runner.Console.Write("  ↑/↓: 選択  Enter/→: 決定")
		runner.Console.Write("  n: Namespace検索  /・f: Pod名検索  r: 両方を編集")
		runner.Console.Write("  c: 条件を消去  b: 戻る  q: 終了")

		action, err := readPodSelectionKey(reader, runner.Streams.In)
		if err != nil {
			return nil, false, err
		}
		switch action {
		case podSelectionUp:
			if len(candidates) > 0 {
				selected = (selected - 1 + len(candidates)) % len(candidates)
			}
		case podSelectionDown:
			if len(candidates) > 0 {
				selected = (selected + 1) % len(candidates)
			}
		case podSelectionHome:
			if len(candidates) > 0 {
				selected = 0
			}
		case podSelectionEnd:
			if len(candidates) > 0 {
				selected = len(candidates) - 1
			}
		case podSelectionPageUp:
			if len(candidates) > 0 {
				selected = max(0, selected-screen.pageSize(len(candidates), hasNotice))
			}
		case podSelectionPageDown:
			if len(candidates) > 0 {
				selected = min(len(candidates)-1, selected+screen.pageSize(len(candidates), hasNotice))
			}
		case podSelectionChoose:
			if len(candidates) == 0 {
				notice = "選択できるPodがありません。検索条件を変更してください。"
				continue
			}
			return candidates[selected].DeepCopy(), false, nil
		case podSelectionNamespaceSearch:
			if runner.Config.Namespace != "" {
				notice = "Namespaceは-nで固定されています。Pod名検索を利用してください。"
				continue
			}
			value, canceled, err := promptPodFilter(reader, runner.Streams.In, runner.Streams.Out, screen, "Namespace検索", namespaceQuery)
			if err != nil {
				return nil, false, err
			}
			if !canceled {
				namespaceQuery, selected = value, 0
			}
		case podSelectionNameSearch:
			value, canceled, err := promptPodFilter(reader, runner.Streams.In, runner.Streams.Out, screen, "Pod名検索", nameQuery)
			if err != nil {
				return nil, false, err
			}
			if !canceled {
				nameQuery, selected = value, 0
			}
		case podSelectionResearch:
			if runner.Config.Namespace == "" {
				value, canceled, err := promptPodFilter(reader, runner.Streams.In, runner.Streams.Out, screen, "Namespace検索", namespaceQuery)
				if err != nil {
					return nil, false, err
				}
				if canceled {
					continue
				}
				namespaceQuery = value
			}
			value, canceled, err := promptPodFilter(reader, runner.Streams.In, runner.Streams.Out, screen, "Pod名検索", nameQuery)
			if err != nil {
				return nil, false, err
			}
			if !canceled {
				nameQuery, selected = value, 0
			}
		case podSelectionClearSearch:
			namespaceQuery, nameQuery, selected = "", "", 0
		case podSelectionBack, podSelectionQuit:
			return nil, true, nil
		case podSelectionInterrupt:
			return nil, false, errPodSelectionInterrupted
		}
	}
}

func podFilterLabel(value string, mask bool) string {
	if value == "" {
		return "（すべて）"
	}
	return console.MaskSecrets(value, mask)
}

func promptPodFilter(reader *bufio.Reader, input io.Reader, output io.Writer, screen *podSelectionScreen, label, current string) (string, bool, error) {
	if err := screen.cursor(true); err != nil {
		return current, false, err
	}
	fmt.Fprintf(output, "\n  %s（部分一致、Enter=全て、bを入力してEnter=変更しない）\n  > ", label)
	line, err := readWizardLine(reader, input, output)
	if err != nil && !errors.Is(err, io.EOF) {
		return current, false, err
	}
	line = strings.TrimSpace(line)
	if strings.EqualFold(line, "b") || errors.Is(err, io.EOF) && line == "" {
		return current, true, nil
	}
	return line, false, nil
}

func readPodSelectionKey(reader *bufio.Reader, input io.Reader) (podSelectionAction, error) {
	file, terminalInput := input.(*os.File)
	fileDescriptor := -1
	var terminalState *term.State
	if terminalInput {
		fileDescriptor = int(file.Fd()) // #nosec G115 -- canonical x/term descriptor conversion.
		terminalInput = term.IsTerminal(fileDescriptor)
	}
	if terminalInput {
		state, err := term.MakeRaw(fileDescriptor)
		if err != nil {
			return podSelectionNone, fmt.Errorf("矢印キー入力を開始できません: %w", err)
		}
		terminalState = state
	}
	action, readErr := readPodSelectionSequence(reader)
	if terminalState != nil {
		if restoreErr := term.Restore(fileDescriptor, terminalState); readErr == nil && restoreErr != nil {
			return podSelectionNone, fmt.Errorf("端末入力を復元できません: %w", restoreErr)
		}
	}
	return action, readErr
}

func readPodSelectionSequence(reader *bufio.Reader) (podSelectionAction, error) {
	value, err := reader.ReadByte()
	if errors.Is(err, io.EOF) {
		return podSelectionQuit, nil
	}
	if err != nil {
		return podSelectionNone, err
	}
	switch value {
	case '\r', '\n':
		return podSelectionChoose, nil
	case ' ':
		return podSelectionToggle, nil
	case 0x03:
		return podSelectionInterrupt, nil
	case 'q', 'Q':
		return podSelectionQuit, nil
	case 'r', 'R':
		return podSelectionResearch, nil
	case 'n', 'N':
		return podSelectionNamespaceSearch, nil
	case '/', 'f', 'F':
		return podSelectionNameSearch, nil
	case 'c', 'C':
		return podSelectionClearSearch, nil
	case 'b', 'B':
		return podSelectionBack, nil
	case 'k', 'K', 0x10:
		return podSelectionUp, nil
	case 'j', 'J', 0x0e:
		return podSelectionDown, nil
	case 0x1b:
		return readPodEscapeSequence(reader)
	default:
		return podSelectionNone, nil
	}
}

func readPodEscapeSequence(reader *bufio.Reader) (podSelectionAction, error) {
	prefix, err := reader.ReadByte()
	if errors.Is(err, io.EOF) {
		return podSelectionNone, nil
	}
	if err != nil {
		return podSelectionNone, err
	}
	if prefix != '[' && prefix != 'O' {
		return podSelectionNone, nil
	}
	parameters := make([]byte, 0, 8)
	for range 16 {
		value, err := reader.ReadByte()
		if errors.Is(err, io.EOF) {
			return podSelectionNone, nil
		}
		if err != nil {
			return podSelectionNone, err
		}
		if value < 0x40 || value > 0x7e {
			parameters = append(parameters, value)
			continue
		}
		switch value {
		case 'A':
			return podSelectionUp, nil
		case 'B':
			return podSelectionDown, nil
		case 'C':
			return podSelectionChoose, nil
		case 'D':
			return podSelectionNone, nil
		case 'H':
			return podSelectionHome, nil
		case 'F':
			return podSelectionEnd, nil
		case '~':
			switch strings.TrimSuffix(string(parameters), ";") {
			case "1", "7":
				return podSelectionHome, nil
			case "4", "8":
				return podSelectionEnd, nil
			case "5":
				return podSelectionPageUp, nil
			case "6":
				return podSelectionPageDown, nil
			}
		case 'M', 'm':
			if prefix != '[' {
				return podSelectionNone, nil
			}
			if len(parameters) == 0 && value == 'M' {
				// X10形式: Mの後ろにボタン、X、Yが各1バイト続く。
				button, readErr := reader.ReadByte()
				if readErr != nil {
					return podSelectionNone, readErr
				}
				for range 2 {
					if _, readErr = reader.ReadByte(); readErr != nil {
						return podSelectionNone, readErr
					}
				}
				return podMouseWheelAction(int(button) - 32), nil
			}
			// SGR形式: <button;x;yM。座標は選択に不要なのでbuttonだけ使う。
			encoded := strings.TrimPrefix(string(parameters), "<")
			buttonText, _, _ := strings.Cut(encoded, ";")
			button, parseErr := strconv.Atoi(buttonText)
			if parseErr == nil {
				return podMouseWheelAction(button), nil
			}
		}
		return podSelectionNone, nil
	}
	return podSelectionNone, nil
}

func podMouseWheelAction(button int) podSelectionAction {
	if button&64 == 0 {
		return podSelectionNone
	}
	switch button & 3 {
	case 0:
		return podSelectionUp
	case 1:
		return podSelectionDown
	default:
		return podSelectionNone
	}
}

func filterPods(pods []corev1.Pod, namespaceQuery, nameQuery string) []corev1.Pod {
	namespaceWords := strings.Fields(strings.ToLower(namespaceQuery))
	nameWords := strings.Fields(strings.ToLower(nameQuery))
	result := make([]corev1.Pod, 0, len(pods))
	for i := range pods {
		if containsAll(strings.ToLower(pods[i].Namespace), namespaceWords) && containsAll(strings.ToLower(pods[i].Name), nameWords) {
			result = append(result, pods[i])
		}
	}
	return result
}

func containsAll(value string, words []string) bool {
	for _, word := range words {
		if !strings.Contains(value, word) {
			return false
		}
	}
	return true
}

func sortedPods(pods []corev1.Pod) []corev1.Pod {
	result := append([]corev1.Pod{}, pods...)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Namespace+"/"+result[i].Name < result[j].Namespace+"/"+result[j].Name
	})
	return result
}

func selectionWindow(total, selected, size int) (int, int) {
	if total <= size {
		return 0, total
	}
	start := selected - size/2
	start = max(0, min(start, total-size))
	return start, start + size
}

func selectionPodRows(pods []corev1.Pod, selected int) []console.TableRow {
	rows := podRows(pods)
	result := make([]console.TableRow, 0, len(rows))
	for index, row := range rows {
		pointer := " "
		if index == selected {
			pointer = "▶"
		}
		result = append(result, console.TableRow{
			Cells: append([]string{pointer}, row.Cells[:4]...), Status: row.Status, Selected: index == selected,
		})
	}
	return result
}

var podSelectionHeaders = []string{"", "NAMESPACE", "NAME", "READY", "STATUS"}

func fitSelectionPodRows(rows []console.TableRow, maxWidth int) []console.TableRow {
	if len(rows) == 0 {
		return rows
	}
	widths := make([]int, len(podSelectionHeaders))
	for index, header := range podSelectionHeaders {
		widths[index] = console.DisplayWidth(header)
	}
	widths[0] = max(widths[0], 1)
	for _, row := range rows {
		for index, value := range row.Cells {
			if index < len(widths) {
				widths[index] = max(widths[index], console.DisplayWidth(value))
			}
		}
	}
	minimums := []int{1, 9, 12, 5, 6}
	lineWidth := func() int {
		total := 2 * (len(widths) - 1)
		for _, width := range widths {
			total += width
		}
		return total
	}
	// Pod名、Namespace、状態のうち、最も余裕がある列から1桁ずつ
	// 縮める。READYと選択マーカーは常に全文を残す。
	shrinkable := []int{2, 1, 4}
	for lineWidth() > maxWidth {
		candidate, excess := -1, 0
		for _, index := range shrinkable {
			if current := widths[index] - minimums[index]; current > excess {
				candidate, excess = index, current
			}
		}
		if candidate < 0 {
			break
		}
		widths[candidate]--
	}

	result := make([]console.TableRow, 0, len(rows))
	for _, row := range rows {
		cells := append([]string{}, row.Cells...)
		for index := range cells {
			if index < len(widths) {
				cells[index] = console.TruncateDisplay(cells[index], widths[index])
			}
		}
		row.Cells = cells
		result = append(result, row)
	}
	return result
}
