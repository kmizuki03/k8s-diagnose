package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
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

func (screen *podSelectionScreen) pageSize(total int) int {
	if !screen.alternate {
		return max(1, total)
	}
	// Header, filters, chapter, legend, table header, position and operation
	// guide use roughly 18 rows. Keep at least three Pods visible on a short
	// terminal and scroll before terminal wrapping corrupts the fifth row.
	return min(max(3, screen.height-18), max(1, total))
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
			runner.Console.Write("  Namespace検索: " + console.MaskSecrets(runner.Config.Namespace, runner.Config.Mask) + " (-nで固定)")
		} else {
			runner.Console.Write("  Namespace検索: " + podFilterLabel(namespaceQuery, runner.Config.Mask) + "  [nで編集]")
		}
		runner.Console.Write("  Pod名検索    : " + podFilterLabel(nameQuery, runner.Config.Mask) + "  [/ または f で編集]")
		if notice != "" {
			runner.Console.Write("  " + notice)
			notice = ""
		}

		candidates := sortedPods(filterPods(pods, namespaceFilter, nameQuery))
		if len(candidates) > 0 {
			selected = min(selected, len(candidates)-1)
			start, end := selectionWindow(len(candidates), selected, screen.pageSize(len(candidates)))
			runner.Console.PodTable([]string{"", "NAMESPACE", "NAME", "READY", "STATUS"}, selectionPodRows(candidates[start:end], selected-start))
			if start > 0 || end < len(candidates) {
				runner.Console.Write(fmt.Sprintf("\n  表示 %d-%d / %d件", start+1, end, len(candidates)))
			}
			runner.Console.Write(fmt.Sprintf("  選択中: %s/%s", candidates[selected].Namespace, candidates[selected].Name))
		} else {
			selected = 0
			runner.Console.PodTable([]string{"", "NAMESPACE", "NAME", "READY", "STATUS"}, nil)
			runner.Console.Write("  ▲ 一致するPodがありません。n または / で検索条件を変更してください。")
		}
		runner.Console.Write("  ↑/↓: 選択  Enter/→: 決定  n: Namespace検索  /・f: Pod名検索")
		runner.Console.Write("  r: 両方を編集  c: 条件を消去  b: 戻る  q: 終了")

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
				selected = max(0, selected-screen.pageSize(len(candidates)))
			}
		case podSelectionPageDown:
			if len(candidates) > 0 {
				selected = min(len(candidates)-1, selected+screen.pageSize(len(candidates)))
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
		return "(全て)"
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
		}
		return podSelectionNone, nil
	}
	return podSelectionNone, nil
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
