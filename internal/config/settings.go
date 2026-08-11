package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// LoadINI implements the deliberately small INI subset used by the Python
// version. Unknown sections and keys fail closed instead of being ignored.
func LoadINI(path string, cfg *Config) error {
	file, err := os.Open(path) // #nosec G304 -- --config explicitly selects the INI file.
	if err != nil {
		return fmt.Errorf("設定ファイルを読み込めません: %s (%w)", path, err)
	}
	defer file.Close()
	return loadINI(file, cfg)
}

// loadINI accepts a reader so the parser can be fuzzed without creating a
// temporary file for every generated input.
func loadINI(reader io.Reader, cfg *Config) error {
	section := ""
	seenSections := map[string]struct{}{}
	seenKeys := map[string]struct{}{}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if !oneOf(section, "target", "diagnosis", "connection", "debug", "display", "report", "history", "notification") {
				return fmt.Errorf("未知の設定セクションです: [%s]", section)
			}
			if _, exists := seenSections[section]; exists {
				return fmt.Errorf("設定セクションが重複しています: [%s]", section)
			}
			seenSections[section] = struct{}{}
			continue
		}
		if section == "" {
			return fmt.Errorf("設定値はセクション内に記述してください (%d行目)", lineNo)
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("設定ファイルの形式が不正です (%d行目)", lineNo)
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		name := section + "." + key
		if !knownSetting(name) {
			return fmt.Errorf("未知の設定です: [%s] %s", section, key)
		}
		if _, exists := seenKeys[name]; exists {
			return fmt.Errorf("設定キーが重複しています: [%s] %s", section, key)
		}
		seenKeys[name] = struct{}{}
		value, err := parseINIValue(parts[1])
		if err != nil {
			return fmt.Errorf("設定ファイルの値が不正です (%d行目): %w", lineNo, err)
		}
		if value == "" {
			continue
		}
		if err := applySetting(cfg, section, key, value); err != nil {
			return fmt.Errorf("設定値が不正です: [%s] %s=%q (%w)", section, key, value, err)
		}
		if cfg.explicitSettings == nil {
			cfg.explicitSettings = map[string]bool{}
		}
		cfg.explicitSettings[name] = true
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("設定ファイルを読み込めません: %w", err)
	}
	inheritLegacyAPIRequestSetting(cfg)
	return nil
}

func inheritLegacyAPIRequestSetting(cfg *Config) {
	if cfg.SettingExplicit("display.show_commands") && !cfg.SettingExplicit("display.show_api_requests") {
		cfg.ShowAPIRequests = cfg.ShowCmd
	}
}

func knownSetting(name string) bool {
	_, exists := settingByName[name]
	return exists
}

func parseINIValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if value[0] == '"' {
		quoted, rest, err := splitQuotedINIValue(value)
		if err != nil {
			return "", err
		}
		if rest != "" && rest[0] != '#' && rest[0] != ';' {
			return "", fmt.Errorf("引用符付き値の後ろにはコメント以外を記述できません")
		}
		decoded, err := strconv.Unquote(quoted)
		if err != nil {
			return "", fmt.Errorf("引用符付き値を解析できません: %w", err)
		}
		return decoded, nil
	}
	return stripInlineComment(value), nil
}

func splitQuotedINIValue(value string) (string, string, error) {
	escaped := false
	for index := 1; index < len(value); index++ {
		switch {
		case escaped:
			escaped = false
		case value[index] == '\\':
			escaped = true
		case value[index] == '"':
			return value[:index+1], strings.TrimSpace(value[index+1:]), nil
		}
	}
	return "", "", fmt.Errorf("引用符が閉じられていません")
}

func stripInlineComment(value string) string {
	value = strings.TrimSpace(value)
	for index := 0; index < len(value); index++ {
		if value[index] != '#' && value[index] != ';' {
			continue
		}
		if index > 0 && (value[index-1] == ' ' || value[index-1] == '\t') {
			return strings.TrimSpace(value[:index])
		}
	}
	return value
}

func applySetting(cfg *Config, section, key, value string) error {
	name := section + "." + key
	boolean := func() (bool, error) {
		switch strings.ToLower(value) {
		case "1", "yes", "true", "on":
			return true, nil
		case "0", "no", "false", "off":
			return false, nil
		default:
			return false, fmt.Errorf("true/false、yes/no、on/off、1/0で指定してください")
		}
	}
	integer := func(minimum int) (int, error) {
		n, err := strconv.Atoi(value)
		if err != nil || n < minimum {
			return 0, fmt.Errorf("%d以上の整数で指定してください", minimum)
		}
		return n, nil
	}
	setBool := func(target *bool) error {
		v, err := boolean()
		if err == nil {
			*target = v
		}
		return err
	}
	setInt := func(target *int, minimum int) error {
		v, err := integer(minimum)
		if err == nil {
			*target = v
		}
		return err
	}
	switch name {
	case "target.namespace":
		cfg.Namespace = value
	case "target.context":
		cfg.Context = value
	case "target.kubeconfig":
		cfg.Kubeconfig = value
	case "target.timeout":
		return setInt(&cfg.RequestTimeout, 1)
	case "target.qps":
		v, err := strconv.ParseFloat(value, 64)
		if err != nil || v <= 0 {
			return fmt.Errorf("0より大きい数値で指定してください")
		}
		cfg.QPS = v
	case "target.burst":
		return setInt(&cfg.Burst, 1)
	case "target.page_size":
		n, err := integer(1)
		if err != nil {
			return err
		}
		cfg.PageSize = int64(n)
	case "diagnosis.mode":
		if !oneOf(value, "all", "select", "list", "triage") {
			return fmt.Errorf("all/select/list/triageから選択してください")
		}
		cfg.Mode = value
	case "diagnosis.logs":
		return setBool(&cfg.ShowLogs)
	case "diagnosis.unused":
		return setBool(&cfg.ShowUnused)
	case "diagnosis.events_limit":
		return setInt(&cfg.EventsLimit, 1)
	case "diagnosis.restart_threshold":
		return setInt(&cfg.RestartThreshold, 0)
	case "diagnosis.node_heartbeat_timeout":
		return setInt(&cfg.NodeHeartbeatTimeout, 1)
	case "diagnosis.watch":
		return setInt(&cfg.Watch, 1)
	case "diagnosis.workers":
		return setInt(&cfg.Workers, 1)
	case "diagnosis.log_signatures_file":
		cfg.LogSignatures = value
	case "diagnosis.log_signature_lines":
		return setInt(&cfg.LogSignatureLines, 1)
	case "connection.enabled":
		return setBool(&cfg.Connect)
	case "connection.port":
		return setInt(&cfg.ConnectPort, 1024)
	case "connection.path":
		cfg.ConnectPath = value
	case "debug.enabled":
		return setBool(&cfg.Debug)
	case "debug.image":
		cfg.DebugImage = value
	case "debug.profile":
		cfg.DebugProfile = value
	case "display.tail":
		return setInt(&cfg.Tail, 1)
	case "display.mask_secrets":
		return setBool(&cfg.Mask)
	case "display.exit_zero":
		return setBool(&cfg.ExitZero)
	case "display.show_commands":
		return setBool(&cfg.ShowCmd)
	case "display.show_api_requests":
		return setBool(&cfg.ShowAPIRequests)
	case "report.format":
		cfg.Output = strings.ToLower(value)
	case "report.file":
		cfg.OutputFile = value
	case "report.save_snapshot":
		cfg.SaveSnapshot = value
	case "report.diff":
		cfg.DiffFrom = value
	case "report.baseline":
		cfg.BaselineFile = value
	case "report.fail_on":
		cfg.FailOn = strings.ToLower(value)
	case "report.max_issues":
		n, err := integer(0)
		if err != nil {
			return err
		}
		cfg.MaxIssues = &n
	case "history.database":
		cfg.HistoryDB = value
	case "history.window":
		return setInt(&cfg.HistoryWindow, 2)
	case "history.flap_threshold":
		return setInt(&cfg.FlapThreshold, 1)
	case "history.restart_growth":
		return setInt(&cfg.RestartGrowth, 1)
	case "history.retain":
		return setInt(&cfg.HistoryRetain, 1)
	case "notification.webhook_url_env":
		cfg.WebhookURLEnv = value
	case "notification.format":
		cfg.WebhookFormat = strings.ToLower(value)
	case "notification.timeout":
		return setInt(&cfg.WebhookTimeout, 1)
	default:
		return fmt.Errorf("未知の設定です")
	}
	return nil
}
