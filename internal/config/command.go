package config

import (
	"errors"
	"fmt"
	"strings"
)

var commandNames = map[string]bool{
	"quick": true, "ci": true, "deep": true,
	"all": true, "pod": true, "list": true, "triage": true,
	"config": true, "advanced": true,
}

// CommandName returns the optional command word at the start of argv. Existing
// flag-only invocations deliberately return an empty command and retain their
// historical behaviour.
func CommandName(args []string) string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return ""
	}
	name := strings.ToLower(strings.TrimSpace(args[0]))
	if commandNames[name] {
		return name
	}
	return ""
}

func splitCommand(args []string) (string, []string) {
	command := CommandName(args)
	if command == "" {
		return "", args
	}
	return command, args[1:]
}

func commandMode(command string) string {
	switch command {
	case "quick", "ci", "triage":
		return "triage"
	case "deep", "all":
		return "all"
	case "pod":
		return "select"
	case "list":
		return "list"
	default:
		return ""
	}
}

// applyCommandProfile overlays a friendly entry point after INI loading and
// before explicit CLI flags. It resets only settings that cannot have meaning
// in the selected mode, so target/API preferences continue to apply.
func applyCommandProfile(cfg *Config, command string) {
	mode := commandMode(command)
	if mode == "" {
		return
	}
	// deep makes log-specific settings relevant in all mode. Set this before
	// prepareMode so a tail/signature configured for Pod diagnosis is retained.
	if command == "deep" {
		cfg.ShowLogs = true
	}
	prepareMode(cfg, mode)
	switch command {
	case "quick":
		clearOneShotAutomation(cfg)
		cfg.Output = "text"
		cfg.OutputFile = ""
		cfg.Mask = true
		cfg.ShowCmd = false
		cfg.ShowAPIRequests = false
		cfg.ExitZero = false
		cfg.FailOn = "issue"
		cfg.MaxIssues = nil
		clearExplicit(cfg, "report.format", "report.file", "display.mask_secrets", "display.show_commands", "display.show_api_requests", "display.exit_zero", "report.fail_on", "report.max_issues")
	case "ci":
		clearOneShotAutomation(cfg)
		cfg.Output = "json"
		cfg.OutputFile = ""
		cfg.Mask = true
		cfg.ShowCmd = false
		cfg.ShowAPIRequests = false
		cfg.ExitZero = false
		cfg.FailOn = "issue"
		cfg.MaxIssues = nil
		clearExplicit(cfg, "diagnosis.events_limit", "report.format", "report.file", "display.mask_secrets", "display.show_commands", "display.show_api_requests", "display.exit_zero", "report.fail_on", "report.max_issues")
	case "deep":
		clearOneShotAutomation(cfg)
		cfg.Output = "text"
		cfg.OutputFile = ""
		cfg.ShowLogs = true
		cfg.ShowUnused = true
		clearExplicit(cfg, "diagnosis.logs", "diagnosis.unused", "report.format", "report.file")
	}
}

func validateConfigEditorArgs(args []string) error {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "--config" || arg == "-config":
			if index+1 >= len(args) {
				return errors.New("configコマンドの--configにはパスが必要です")
			}
			index++
		case strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config="):
		case arg == "--no-config" || arg == "-no-config" || strings.HasPrefix(arg, "--no-config=") || strings.HasPrefix(arg, "-no-config=") ||
			arg == "-h" || arg == "--help" || strings.HasPrefix(arg, "-h=") || strings.HasPrefix(arg, "--help=") ||
			arg == "--version" || arg == "-version" || strings.HasPrefix(arg, "--version=") || strings.HasPrefix(arg, "-version="):
		default:
			return fmt.Errorf("configコマンドでは%sを使用できません（設定値は対話画面で変更してください）", arg)
		}
	}
	return nil
}

func prepareMode(cfg *Config, mode string) {
	cfg.Mode = mode
	clearExplicit(cfg, "diagnosis.mode")
	switch mode {
	case "all":
		clearConnection(cfg)
		if !cfg.ShowLogs {
			clearLogOptions(cfg)
		}
	case "select":
		cfg.ShowLogs = false
		cfg.ShowUnused = false
		cfg.Watch = 0
		cfg.Output = "text"
		cfg.OutputFile = ""
		cfg.SaveSnapshot = ""
		cfg.DiffFrom = ""
		cfg.HistoryDB = ""
		cfg.WebhookURLEnv = ""
		cfg.FailOn = Defaults().FailOn
		cfg.MaxIssues = nil
		clearExplicit(cfg,
			"diagnosis.logs", "diagnosis.unused", "diagnosis.watch", "diagnosis.node_heartbeat_timeout",
			"report.format", "report.file", "report.save_snapshot", "report.diff", "report.fail_on", "report.max_issues",
			"history.database", "history.window", "history.flap_threshold", "history.restart_growth", "history.retain",
			"notification.webhook_url_env", "notification.format", "notification.timeout",
		)
	case "list":
		cfg.ShowLogs = false
		cfg.ShowUnused = false
		cfg.EventsLimit = Defaults().EventsLimit
		cfg.RestartThreshold = Defaults().RestartThreshold
		cfg.Watch = 0
		cfg.Output = "text"
		cfg.OutputFile = ""
		cfg.SaveSnapshot = ""
		cfg.DiffFrom = ""
		cfg.BaselineFile = ""
		cfg.HistoryDB = ""
		cfg.WebhookURLEnv = ""
		cfg.ExitZero = false
		cfg.FailOn = Defaults().FailOn
		cfg.MaxIssues = nil
		clearConnection(cfg)
		clearDebug(cfg)
		clearLogOptions(cfg)
		clearExplicit(cfg,
			"diagnosis.logs", "diagnosis.unused", "diagnosis.events_limit", "diagnosis.restart_threshold", "diagnosis.node_heartbeat_timeout", "diagnosis.watch",
			"display.exit_zero", "report.format", "report.file", "report.save_snapshot", "report.diff", "report.baseline", "report.fail_on", "report.max_issues",
			"history.database", "history.window", "history.flap_threshold", "history.restart_growth", "history.retain",
			"notification.webhook_url_env", "notification.format", "notification.timeout",
		)
	case "triage":
		cfg.ShowLogs = false
		cfg.ShowUnused = false
		clearConnection(cfg)
		clearDebug(cfg)
		clearLogOptions(cfg)
		clearExplicit(cfg, "diagnosis.logs", "diagnosis.unused")
	}
}

func clearConnection(cfg *Config) {
	cfg.Connect = false
	cfg.ConnectPort = 0
	cfg.ConnectPath = ""
	clearExplicit(cfg, "connection.enabled", "connection.port", "connection.path")
}

func clearDebug(cfg *Config) {
	cfg.Debug = false
	cfg.DebugImage = Defaults().DebugImage
	cfg.DebugProfile = Defaults().DebugProfile
	clearExplicit(cfg, "debug.enabled", "debug.image", "debug.profile")
}

func clearLogOptions(cfg *Config) {
	cfg.LogSignatures = ""
	cfg.LogSignatureLines = Defaults().LogSignatureLines
	cfg.Tail = Defaults().Tail
	clearExplicit(cfg, "diagnosis.log_signatures_file", "diagnosis.log_signature_lines", "display.tail")
}

func clearOneShotAutomation(cfg *Config) {
	cfg.Watch = 0
	cfg.SaveSnapshot = ""
	cfg.DiffFrom = ""
	cfg.HistoryDB = ""
	cfg.WebhookURLEnv = ""
	clearExplicit(cfg,
		"diagnosis.watch", "report.save_snapshot", "report.diff",
		"history.database", "history.window", "history.flap_threshold", "history.restart_growth", "history.retain",
		"notification.webhook_url_env", "notification.format", "notification.timeout",
	)
}

func clearExplicit(cfg *Config, names ...string) {
	for _, name := range names {
		delete(cfg.explicitSettings, name)
	}
}

// CommandDescription is the short user-facing explanation used by the root
// menu and command-specific help.
func CommandDescription(command string) string {
	switch command {
	case "quick":
		return "短時間のtriageをtextで実行"
	case "ci":
		return "triageをJSON出力し、確定異常で失敗"
	case "deep":
		return "全体診断にログ・未使用候補を追加"
	case "all":
		return "クラスタ全体を診断"
	case "pod":
		return "Podを選んで個別診断"
	case "list":
		return "Pod一覧のみ表示"
	case "triage":
		return "CI/初動向け診断"
	case "config":
		return "対話式にINI設定を編集"
	case "advanced":
		return "従来の全フラグを使用"
	default:
		return fmt.Sprintf("未知のコマンド %q", command)
	}
}

// ApplyProfile applies a friendly command profile without parsing another
// argv. The guided UI uses the same profiles as the one-word CLI commands.
func ApplyProfile(cfg Config, command string) (Config, error) {
	if commandMode(command) == "" {
		return cfg, fmt.Errorf("診断プロファイルではありません: %s", command)
	}
	candidate := cfg
	candidate.explicitSettings = cloneExplicitSettings(cfg.explicitSettings)
	applyCommandProfile(&candidate, command)
	if err := candidate.Validate(nil); err != nil {
		return cfg, err
	}
	return candidate, nil
}
