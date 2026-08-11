package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type SettingSpec struct {
	Name        string
	Section     string
	Key         string
	Label       string
	Description string
	Boolean     bool
}

func setting(section, key, label, description string) SettingSpec {
	return SettingSpec{Name: section + "." + key, Section: section, Key: key, Label: label, Description: description}
}

func booleanSetting(section, key, label, description string) SettingSpec {
	spec := setting(section, key, label, description)
	spec.Boolean = true
	return spec
}

var settingCatalog = []SettingSpec{
	setting("target", "namespace", "Namespace", "空欄の場合は、すべてのNamespaceを対象にします"),
	setting("target", "context", "Context", "使用するkubeconfigのcontext"),
	setting("target", "kubeconfig", "Kubeconfig", "使用するkubeconfigファイル"),
	setting("target", "timeout", "APIタイムアウト", "Kubernetes API要求のタイムアウト秒数"),
	setting("target", "qps", "Client QPS", "client-goクライアントのQPS"),
	setting("target", "burst", "Client burst", "client-goクライアントのBurst値"),
	setting("target", "page_size", "ページサイズ", "List APIで1回に取得する件数"),

	setting("diagnosis", "mode", "既定モード", "all、select、list、triage のいずれか"),
	booleanSetting("diagnosis", "logs", "全体診断ログ", "allモードで異常なPodのログを取得します"),
	booleanSetting("diagnosis", "unused", "未使用候補", "allモードで未使用リソースの候補を診断します"),
	setting("diagnosis", "events_limit", "Event表示数", "表示する最新のWarning Event件数"),
	setting("diagnosis", "restart_threshold", "再起動閾値", "再起動警告の回数"),
	setting("diagnosis", "node_heartbeat_timeout", "Nodeハートビート", "Leaseの停滞と判定する秒数"),
	setting("diagnosis", "watch", "Watch間隔", "0ではなく1以上の秒数で定期実行"),
	setting("diagnosis", "workers", "並列取得数", "1〜16"),
	setting("diagnosis", "log_signatures_file", "ログシグネチャINI", "追加のログシグネチャ定義ファイル"),
	setting("diagnosis", "log_signature_lines", "ログ解析行数", "末尾1〜5000行"),

	booleanSetting("connection", "enabled", "接続確認", "一時的なport-forwardを作成し、ProbeまたはTCP接続を確認します（実行前の追加確認なし）"),
	setting("connection", "port", "ローカルポート", "1024〜65535、未設定なら自動"),
	setting("connection", "path", "HTTPパス", "「/」で始まる上書き用のパス"),

	booleanSetting("debug", "enabled", "Debugメニュー", "allまたはselectモードの診断後に表示します"),
	setting("debug", "image", "Debugイメージ", "kubectl debugで使用するコンテナイメージ"),
	setting("debug", "profile", "Debugプロファイル", "kubectl debugで使用するプロファイル"),

	setting("display", "tail", "ログ表示行数", "selectモードまたはallモードのログ診断で使用します"),
	booleanSetting("display", "mask_secrets", "秘匿情報マスク", "通常は有効を推奨"),
	booleanSetting("display", "exit_zero", "常にexit 0", "所見による失敗を抑止"),
	booleanSetting("display", "show_commands", "確認コマンド", "各診断項目で使用できる同等のkubectlコマンドを表示します"),
	booleanSetting("display", "show_api_requests", "実API要求", "末尾に実行したKubernetes API要求を表示"),

	setting("report", "format", "出力形式", "text、json、sarif、junit、mermaid、dot のいずれか"),
	setting("report", "file", "レポート保存先", "構造化出力の保存先"),
	setting("report", "save_snapshot", "スナップショット保存先", "今回の診断結果をJSON形式で保存します"),
	setting("report", "diff", "比較スナップショット", "保存済みの診断結果と比較します"),
	setting("report", "baseline", "ベースライン", "承認済み所見を定義したINIファイル"),
	setting("report", "fail_on", "CI失敗重大度", "issue、warning、unavailable、any、none のいずれか"),
	setting("report", "max_issues", "許容件数", "fail_onの対象として許容する最大件数"),

	setting("history", "database", "履歴DB", "SQLite履歴ファイル"),
	setting("history", "window", "履歴ウィンドウ", "分析対象とする過去の実行回数"),
	setting("history", "flap_threshold", "フラッピング閾値", "フラッピングと判定する状態遷移回数"),
	setting("history", "restart_growth", "再起動増加閾値", "restartCount増加数"),
	setting("history", "retain", "履歴保持数", "DB全体の最大実行数"),

	setting("notification", "webhook_url_env", "Webhook URL環境変数", "HTTPS URLを保持する環境変数名"),
	setting("notification", "format", "Webhook形式", "generic または slack"),
	setting("notification", "timeout", "Webhookタイムアウト", "送信のタイムアウト秒数"),
}

var settingByName = func() map[string]SettingSpec {
	result := make(map[string]SettingSpec, len(settingCatalog))
	for _, spec := range settingCatalog {
		result[spec.Name] = spec
	}
	return result
}()

func SettingCatalog() []SettingSpec {
	return append([]SettingSpec{}, settingCatalog...)
}

func (c Config) SettingExplicit(name string) bool {
	return c.explicitSettings[name]
}

func (c Config) SettingValue(name string) string {
	switch name {
	case "target.namespace":
		return c.Namespace
	case "target.context":
		return c.Context
	case "target.kubeconfig":
		return c.Kubeconfig
	case "target.timeout":
		return strconv.Itoa(c.RequestTimeout)
	case "target.qps":
		return strconv.FormatFloat(c.QPS, 'g', -1, 64)
	case "target.burst":
		return strconv.Itoa(c.Burst)
	case "target.page_size":
		return strconv.FormatInt(c.PageSize, 10)
	case "diagnosis.mode":
		return c.Mode
	case "diagnosis.logs":
		return strconv.FormatBool(c.ShowLogs)
	case "diagnosis.unused":
		return strconv.FormatBool(c.ShowUnused)
	case "diagnosis.events_limit":
		return strconv.Itoa(c.EventsLimit)
	case "diagnosis.restart_threshold":
		return strconv.Itoa(c.RestartThreshold)
	case "diagnosis.node_heartbeat_timeout":
		return strconv.Itoa(c.NodeHeartbeatTimeout)
	case "diagnosis.watch":
		if c.Watch == 0 {
			return ""
		}
		return strconv.Itoa(c.Watch)
	case "diagnosis.workers":
		return strconv.Itoa(c.Workers)
	case "diagnosis.log_signatures_file":
		return c.LogSignatures
	case "diagnosis.log_signature_lines":
		return strconv.Itoa(c.LogSignatureLines)
	case "connection.enabled":
		return strconv.FormatBool(c.Connect)
	case "connection.port":
		if c.ConnectPort == 0 {
			return ""
		}
		return strconv.Itoa(c.ConnectPort)
	case "connection.path":
		return c.ConnectPath
	case "debug.enabled":
		return strconv.FormatBool(c.Debug)
	case "debug.image":
		return c.DebugImage
	case "debug.profile":
		return c.DebugProfile
	case "display.tail":
		return strconv.Itoa(c.Tail)
	case "display.mask_secrets":
		return strconv.FormatBool(c.Mask)
	case "display.exit_zero":
		return strconv.FormatBool(c.ExitZero)
	case "display.show_commands":
		return strconv.FormatBool(c.ShowCmd)
	case "display.show_api_requests":
		return strconv.FormatBool(c.ShowAPIRequests)
	case "report.format":
		return c.Output
	case "report.file":
		return c.OutputFile
	case "report.save_snapshot":
		return c.SaveSnapshot
	case "report.diff":
		return c.DiffFrom
	case "report.baseline":
		return c.BaselineFile
	case "report.fail_on":
		return c.FailOn
	case "report.max_issues":
		if c.MaxIssues == nil {
			return ""
		}
		return strconv.Itoa(*c.MaxIssues)
	case "history.database":
		return c.HistoryDB
	case "history.window":
		return strconv.Itoa(c.HistoryWindow)
	case "history.flap_threshold":
		return strconv.Itoa(c.FlapThreshold)
	case "history.restart_growth":
		return strconv.Itoa(c.RestartGrowth)
	case "history.retain":
		return strconv.Itoa(c.HistoryRetain)
	case "notification.webhook_url_env":
		return c.WebhookURLEnv
	case "notification.format":
		return c.WebhookFormat
	case "notification.timeout":
		return strconv.Itoa(c.WebhookTimeout)
	default:
		return ""
	}
}

func cloneExplicitSettings(values map[string]bool) map[string]bool {
	result := make(map[string]bool, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

// WithSetting applies the same parser and complete combination validation used
// by INI and CLI configuration. The receiver is unchanged when validation
// fails, which keeps an interactive editing session in a valid state.
func (c Config) WithSetting(name, value string) (Config, error) {
	if !knownSetting(name) {
		return c, fmt.Errorf("未知の設定です: %s", name)
	}
	candidate := c
	candidate.explicitSettings = cloneExplicitSettings(c.explicitSettings)
	spec := settingByName[name]
	if err := applySetting(&candidate, spec.Section, spec.Key, value); err != nil {
		return c, fmt.Errorf("設定値が不正です: [%s] %s=%q（理由: %w）", spec.Section, spec.Key, value, err)
	}
	candidate.explicitSettings[name] = true
	inheritLegacyAPIRequestSetting(&candidate)
	if err := candidate.Validate(nil); err != nil {
		return c, err
	}
	return candidate, nil
}

func (c Config) WithoutSetting(name string) (Config, error) {
	if !knownSetting(name) {
		return c, fmt.Errorf("未知の設定です: %s", name)
	}
	candidate := c
	candidate.explicitSettings = cloneExplicitSettings(c.explicitSettings)
	defaults := Defaults()
	switch name {
	case "diagnosis.watch":
		candidate.Watch = 0
	case "connection.port":
		candidate.ConnectPort = 0
	case "report.max_issues":
		candidate.MaxIssues = nil
	default:
		spec := settingByName[name]
		if err := applySetting(&candidate, spec.Section, spec.Key, defaults.SettingValue(name)); err != nil {
			return c, err
		}
	}
	delete(candidate.explicitSettings, name)
	if name == "display.show_commands" && !candidate.SettingExplicit("display.show_api_requests") {
		candidate.ShowAPIRequests = defaults.ShowAPIRequests
	}
	inheritLegacyAPIRequestSetting(&candidate)
	if err := candidate.Validate(nil); err != nil {
		return c, err
	}
	return candidate, nil
}

func RenderINI(c Config) ([]byte, error) {
	if err := c.Validate(nil); err != nil {
		return nil, fmt.Errorf("設定を保存できません: %w", err)
	}
	buffer := &bytes.Buffer{}
	fmt.Fprintln(buffer, "# k8s-diagnose 設定")
	fmt.Fprintln(buffer, "# 空欄は組み込み既定値です。プリセット、CLI引数の順にこのファイルより優先されます。")
	section := ""
	for _, spec := range settingCatalog {
		if spec.Section != section {
			section = spec.Section
			fmt.Fprintf(buffer, "\n[%s]\n", section)
		}
		value := ""
		if c.SettingExplicit(spec.Name) {
			value = strconv.Quote(c.SettingValue(spec.Name))
		}
		fmt.Fprintf(buffer, "# %s: %s\n%s = %s\n", spec.Label, spec.Description, spec.Key, value)
	}
	return buffer.Bytes(), nil
}

func SaveINI(path string, c Config) (string, error) {
	if path == "" {
		var err error
		path, err = DefaultConfigPath()
		if err != nil {
			return "", err
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("設定保存先を解決できません: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
		absolute = resolved
	}
	validated := c
	validated.ConfigFile = absolute
	data, err := RenderINI(validated)
	if err != nil {
		return "", err
	}
	directory := filepath.Dir(absolute)
	temporary, err := os.CreateTemp(directory, ".k8s-diagnose.ini.tmp-*")
	if err != nil {
		return "", fmt.Errorf("設定の一時ファイルを作成できません: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", fmt.Errorf("設定ファイルの権限を設定できません: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return "", fmt.Errorf("設定を書き込めません: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("設定を同期できません: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("設定を閉じられません: %w", err)
	}
	if err := os.Rename(temporaryPath, absolute); err != nil {
		return "", fmt.Errorf("設定を置き換えられません: %w", err)
	}
	committed = true
	if runtime.GOOS != "windows" {
		parent, err := os.Open(directory) // #nosec G304 -- parent of the explicit settings path is intentionally opened for fsync.
		if err != nil {
			return "", fmt.Errorf("設定保存先ディレクトリを開けません: %w", err)
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if syncErr != nil {
			return "", fmt.Errorf("設定保存先ディレクトリを同期できません: %w", syncErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("設定保存先ディレクトリを閉じられません: %w", closeErr)
		}
	}
	return absolute, nil
}

// SettingSummary formats one setting for the interactive editor while making
// it clear whether the value is explicitly persisted or inherited.
func SettingSummary(c Config, spec SettingSpec) string {
	value := c.SettingValue(spec.Name)
	if spec.Boolean {
		switch strings.ToLower(value) {
		case "true":
			value = "有効（true）"
		case "false":
			value = "無効（false）"
		}
	}
	if value == "" {
		value = "（空欄）"
	}
	if !c.SettingExplicit(spec.Name) {
		value += "［組み込み既定］"
	}
	return strings.TrimSpace(value)
}
