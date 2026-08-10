package rules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kmizuki03/k8s-diagnose/internal/console"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

type LogAnalyzer struct {
	signatures []logSignature
	lastLines  int
}

type logSignature struct {
	ID, Code, Title string
	Pattern         *regexp.Regexp
	Severity        model.Severity
	Confidence      int
	Minimum         int
}

var builtInLogSignatures = []logSignature{
	{"oom", "K8S.LOG.OOM", "Out of Memoryの痕跡", regexp.MustCompile(`(?i)\b(?:oomkilled|out of memory|cannot allocate memory|memory cgroup out of memory)\b`), model.Warning, 85, 1},
	{"go_panic", "K8S.LOG.GO_PANIC", "Go panic", regexp.MustCompile(`(?m)^panic:\s+`), model.Warning, 85, 1},
	{"python_traceback", "K8S.LOG.PYTHON_TRACEBACK", "Python Traceback", regexp.MustCompile(`(?m)^Traceback \(most recent call last\):`), model.Warning, 80, 1},
	{"x509_expired", "K8S.LOG.X509_EXPIRED", "X.509証明書の期限切れ", regexp.MustCompile(`(?i)(?:x509|certificate).{0,80}(?:expired|has expired|not valid after)`), model.Warning, 90, 1},
	{"address_in_use", "K8S.LOG.ADDRESS_IN_USE", "listen addressの競合", regexp.MustCompile(`(?i)(?:bind|listen).{0,80}address already in use`), model.Warning, 85, 1},
	{"network_unreachable", "K8S.LOG.NETWORK_UNREACHABLE", "通信先への接続失敗", regexp.MustCompile(`(?i)connection refused|no route to host`), model.Candidate, 55, 2},
	{"permission_denied", "K8S.LOG.PERMISSION_DENIED", "permission denied", regexp.MustCompile(`(?i)permission denied`), model.Candidate, 50, 2},
	{"connection_reset", "K8S.LOG.CONNECTION_RESET", "connection reset by peer", regexp.MustCompile(`(?i)connection reset by peer`), model.Candidate, 50, 2},
}

// AnalyzeLogs matches raw text, but every persisted evidence line is always
// masked even when the user disabled ordinary terminal masking.
func AnalyzeLogs(namespace, pod, source, text string, lastLines int) []model.Finding {
	return (&LogAnalyzer{signatures: append([]logSignature{}, builtInLogSignatures...), lastLines: lastLines}).Analyze(namespace, pod, source, text)
}

func NewLogAnalyzer(path string, lastLines int) (*LogAnalyzer, error) {
	signatures := append([]logSignature{}, builtInLogSignatures...)
	if path == "" {
		return &LogAnalyzer{signatures: signatures, lastLines: lastLines}, nil
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, fmt.Errorf("ログシグネチャ設定を読み込めません: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return nil, fmt.Errorf("ログシグネチャ設定は1MiB以下の通常ファイルにしてください")
	}
	file, err := os.Open(absolute) // #nosec G304 -- --log-signatures explicitly selects a validated regular file.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	sections := map[string]map[string]string{}
	section := ""
	scanner := bufio.NewScanner(file)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section != "settings" && !strings.HasPrefix(section, "signature.") {
				return nil, fmt.Errorf("未知のセクションです: [%s]", section)
			}
			if sections[section] != nil {
				return nil, fmt.Errorf("セクションが重複しています: [%s]", section)
			}
			sections[section] = map[string]string{}
			continue
		}
		if section == "" {
			return nil, fmt.Errorf("設定値はセクション内に記述してください (%d行目)", lineNo)
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("設定形式が不正です (%d行目)", lineNo)
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if _, exists := sections[section][key]; exists {
			return nil, fmt.Errorf("[%s]のキーが重複しています: %s", section, key)
		}
		sections[section][key] = strings.TrimSpace(parts[1])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	disabled := map[string]struct{}{}
	if settings := sections["settings"]; settings != nil {
		for key := range settings {
			if key != "disabled" {
				return nil, fmt.Errorf("[settings]の未知のキーです: %s", key)
			}
		}
		for _, value := range strings.Split(settings["disabled"], ",") {
			if value = strings.TrimSpace(value); value != "" {
				disabled[value] = struct{}{}
			}
		}
	}
	known := map[string]struct{}{}
	filtered := []logSignature{}
	for _, signature := range signatures {
		known[signature.ID] = struct{}{}
		if _, off := disabled[signature.ID]; !off {
			filtered = append(filtered, signature)
		}
	}
	for id := range disabled {
		if _, ok := known[id]; !ok {
			return nil, fmt.Errorf("無効化対象の組み込みシグネチャが存在しません: %s", id)
		}
	}
	customCount := 0
	for name, values := range sections {
		if !strings.HasPrefix(name, "signature.") {
			continue
		}
		id := strings.TrimPrefix(name, "signature.")
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`).MatchString(id) {
			return nil, fmt.Errorf("ログシグネチャIDが不正です: %q", id)
		}
		if _, exists := known[id]; exists {
			return nil, fmt.Errorf("ログシグネチャIDが重複しています: %s", id)
		}
		for key := range values {
			switch key {
			case "pattern", "title", "severity", "confidence", "min_count", "case_sensitive":
			default:
				return nil, fmt.Errorf("[%s]の未知のキーです: %s", name, key)
			}
		}
		pattern, title := values["pattern"], strings.Join(strings.Fields(values["title"]), " ")
		if pattern == "" || title == "" || utf8.RuneCountInString(pattern) > 500 || utf8.RuneCountInString(title) > 500 {
			return nil, fmt.Errorf("[%s]には500文字以下のpatternとtitleが必要です", name)
		}
		caseSensitive, err := parseLogBool(values["case_sensitive"], false)
		if err != nil {
			return nil, fmt.Errorf("[%s] case_sensitive: %w", name, err)
		}
		if !caseSensitive {
			pattern = "(?i)" + pattern
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil || compiled.MatchString("") {
			return nil, fmt.Errorf("[%s] patternが不正または空文字に一致します", name)
		}
		severity := model.Candidate
		if values["severity"] == "warning" {
			severity = model.Warning
		} else if values["severity"] != "" && values["severity"] != "candidate" {
			return nil, fmt.Errorf("[%s] severityはwarningまたはcandidateです", name)
		}
		confidence, err := parseLogInt(values["confidence"], 60, 0, 100)
		if err != nil {
			return nil, fmt.Errorf("[%s] confidence: %w", name, err)
		}
		minimum, err := parseLogInt(values["min_count"], 2, 1, 100)
		if err != nil {
			return nil, fmt.Errorf("[%s] min_count: %w", name, err)
		}
		code := "K8S.LOG." + strings.ToUpper(regexp.MustCompile(`[^A-Z0-9]+`).ReplaceAllString(strings.ToUpper(id), "_"))
		filtered = append(filtered, logSignature{id, code, title, compiled, severity, confidence, minimum})
		known[id] = struct{}{}
		customCount++
		if customCount > 50 {
			return nil, fmt.Errorf("カスタムログシグネチャは50件までです")
		}
	}
	return &LogAnalyzer{signatures: filtered, lastLines: lastLines}, nil
}

func parseLogBool(value string, fallback bool) (bool, error) {
	if value == "" {
		return fallback, nil
	}
	switch strings.ToLower(value) {
	case "1", "yes", "true", "on":
		return true, nil
	case "0", "no", "false", "off":
		return false, nil
	default:
		return false, fmt.Errorf("true/falseで指定してください")
	}
}

func parseLogInt(value string, fallback, minimum, maximum int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < minimum || number > maximum {
		return 0, fmt.Errorf("%d以上%d以下の整数で指定してください", minimum, maximum)
	}
	return number, nil
}

func (analyzer *LogAnalyzer) Analyze(namespace, pod, source, text string) []model.Finding {
	lines := strings.Split(text, "\n")
	if len(lines) > analyzer.lastLines {
		lines = lines[len(lines)-analyzer.lastLines:]
	}
	window := strings.Join(lines, "\n")
	result := []model.Finding{}
	for _, signature := range analyzer.signatures {
		matches := signature.Pattern.FindAllStringIndex(window, -1)
		if len(matches) < signature.Minimum {
			continue
		}
		evidence := []model.Evidence{{Kind: "log", Key: "source", Value: source}, {Kind: "log", Key: "count", Value: fmt.Sprint(len(matches))}}
		for _, line := range lines {
			if signature.Pattern.MatchString(line) {
				evidence = append(evidence, model.Evidence{Kind: "log", Key: "match", Value: console.MaskSecrets(strings.TrimSpace(line), true)})
				if len(evidence) >= 5 {
					break
				}
			}
		}
		result = append(result, model.NewFinding(
			signature.Severity, signature.Code, "ログ", ref("Pod", namespace, pod), signature.ID,
			source+"/"+signature.ID, fmt.Sprintf("Pod %s: %sをログ末尾で%d回検出", shortRef(namespace, pod), signature.Title, len(matches)), signature.Confidence, evidence...,
		))
	}
	return result
}
