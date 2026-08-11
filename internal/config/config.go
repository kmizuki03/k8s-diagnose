// Package config parses CLI and INI configuration and validates combinations.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/redact"
)

// Version is a variable so release builds can inject the Git tag with
// -ldflags "-X github.com/kmizuki03/k8s-diagnose/internal/config.Version=...".
var Version = "3.0.0-dev"

type Config struct {
	ConfigFile           string
	Mode                 string
	Namespace            string
	Context              string
	Kubeconfig           string
	ShowLogs             bool
	ShowUnused           bool
	Debug                bool
	DebugImage           string
	DebugProfile         string
	Connect              bool
	ConnectPort          int
	ConnectPath          string
	EventsLimit          int
	Tail                 int
	RestartThreshold     int
	NodeHeartbeatTimeout int
	RequestTimeout       int
	Watch                int
	Mask                 bool
	ExitZero             bool
	ShowCmd              bool
	ShowAPIRequests      bool
	Output               string
	OutputFile           string
	SaveSnapshot         string
	DiffFrom             string
	FailOn               string
	MaxIssues            *int
	Workers              int
	QPS                  float64
	Burst                int
	PageSize             int64
	HistoryDB            string
	HistoryWindow        int
	FlapThreshold        int
	RestartGrowth        int
	HistoryRetain        int
	WebhookURLEnv        string
	WebhookFormat        string
	WebhookTimeout       int
	LogSignatures        string
	LogSignatureLines    int
	BaselineFile         string
	Version              bool
	explicitSettings     map[string]bool
}

func Defaults() Config {
	return Config{
		Mode: "all", DebugImage: "busybox:1.36", DebugProfile: "general",
		EventsLimit: 20, Tail: 30, RestartThreshold: 5, NodeHeartbeatTimeout: 180, RequestTimeout: 15,
		Mask: true, ShowCmd: true, ShowAPIRequests: true, Output: "text", FailOn: "issue", Workers: 4,
		QPS: 10, Burst: 20, PageSize: 500,
		HistoryWindow: 12, FlapThreshold: 3, RestartGrowth: 3, HistoryRetain: 1000,
		WebhookFormat: "generic", WebhookTimeout: 5, LogSignatureLines: 200,
		explicitSettings: map[string]bool{},
	}
}

func (c Config) ScopeLabel() string {
	if c.Namespace == "" {
		return "全て"
	}
	return c.Namespace
}

func Parse(args []string, prog string) (Config, error) {
	command, args := splitCommand(args)
	cfg := Defaults()
	if command == "config" {
		if err := validateConfigEditorArgs(args); err != nil {
			return cfg, err
		}
	}
	configPath, err := findConfigPath(args)
	if err != nil {
		return cfg, err
	}
	noConfig, err := booleanOptionEnabled(args, "--no-config", "-no-config")
	if err != nil {
		return cfg, err
	}
	if noConfig && configPath != "" {
		return cfg, errors.New("--config と --no-config は同時に指定できません")
	}
	helpRequested, err := booleanOptionEnabled(args, "-h", "--help")
	if err != nil {
		return cfg, err
	}
	versionRequested, err := booleanOptionEnabled(args, "--version", "-version")
	if err != nil {
		return cfg, err
	}
	if configPath == "" && !noConfig && !helpRequested && !versionRequested {
		configPath, err = ExistingDefaultConfig()
		if err != nil {
			return cfg, err
		}
	}
	if configPath != "" {
		if err := LoadINI(configPath, &cfg); err != nil {
			if command != "config" || !errors.Is(err, os.ErrNotExist) {
				return cfg, err
			}
		}
		absolute, err := filepath.Abs(configPath)
		if err != nil {
			return cfg, fmt.Errorf("設定ファイルのパスを解決できません: %w", err)
		}
		cfg.ConfigFile = absolute
	}
	applyCommandProfile(&cfg, command)

	fs := flag.NewFlagSet(prog, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var all, selectMode, list, triage bool
	var noMask, noCmd, showCmd bool
	var noAPIRequests, showAPIRequests bool
	var maxIssues optionalInt
	if cfg.MaxIssues != nil {
		maxIssues.set, maxIssues.value = true, *cfg.MaxIssues
	}
	fs.BoolVar(&all, "a", false, "")
	fs.BoolVar(&all, "all", false, "")
	fs.BoolVar(&selectMode, "s", false, "")
	fs.BoolVar(&selectMode, "select", false, "")
	fs.BoolVar(&list, "p", false, "")
	fs.BoolVar(&list, "list", false, "")
	fs.BoolVar(&list, "pods", false, "")
	fs.BoolVar(&triage, "triage", false, "")
	// findConfigPath already loaded and canonicalized this value. Parse the
	// flag again only so flag.FlagSet accepts it; do not replace the absolute
	// path retained for reports with the original relative spelling.
	parsedConfigPath := cfg.ConfigFile
	fs.StringVar(&parsedConfigPath, "config", parsedConfigPath, "")
	fs.BoolVar(&noConfig, "no-config", noConfig, "")
	fs.StringVar(&cfg.Namespace, "n", cfg.Namespace, "")
	fs.StringVar(&cfg.Namespace, "namespace", cfg.Namespace, "")
	fs.StringVar(&cfg.Context, "context", cfg.Context, "")
	fs.StringVar(&cfg.Kubeconfig, "kubeconfig", cfg.Kubeconfig, "")
	fs.IntVar(&cfg.RequestTimeout, "timeout", cfg.RequestTimeout, "")
	fs.BoolVar(&cfg.ShowLogs, "logs", cfg.ShowLogs, "")
	fs.BoolVar(&cfg.ShowUnused, "unused", cfg.ShowUnused, "")
	fs.StringVar(&cfg.LogSignatures, "log-signatures", cfg.LogSignatures, "")
	fs.IntVar(&cfg.LogSignatureLines, "log-signature-lines", cfg.LogSignatureLines, "")
	fs.IntVar(&cfg.EventsLimit, "events-limit", cfg.EventsLimit, "")
	fs.IntVar(&cfg.RestartThreshold, "restart-threshold", cfg.RestartThreshold, "")
	fs.IntVar(&cfg.NodeHeartbeatTimeout, "node-heartbeat-timeout", cfg.NodeHeartbeatTimeout, "")
	fs.BoolVar(&cfg.Connect, "connect", cfg.Connect, "")
	fs.IntVar(&cfg.ConnectPort, "connect-port", cfg.ConnectPort, "")
	fs.StringVar(&cfg.ConnectPath, "connect-path", cfg.ConnectPath, "")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "")
	fs.StringVar(&cfg.DebugImage, "debug-image", cfg.DebugImage, "")
	fs.StringVar(&cfg.DebugProfile, "debug-profile", cfg.DebugProfile, "")
	fs.IntVar(&cfg.Tail, "tail", cfg.Tail, "")
	fs.BoolVar(&noMask, "no-mask", false, "")
	fs.IntVar(&cfg.Watch, "w", cfg.Watch, "")
	fs.IntVar(&cfg.Watch, "watch", cfg.Watch, "")
	fs.BoolVar(&cfg.ExitZero, "exit-zero", cfg.ExitZero, "")
	fs.BoolVar(&showCmd, "cmd", false, "")
	fs.BoolVar(&noCmd, "no-cmd", false, "")
	fs.BoolVar(&showAPIRequests, "api-requests", false, "")
	fs.BoolVar(&noAPIRequests, "no-api-requests", false, "")
	fs.StringVar(&cfg.Output, "output", cfg.Output, "")
	fs.StringVar(&cfg.OutputFile, "output-file", cfg.OutputFile, "")
	fs.StringVar(&cfg.SaveSnapshot, "save-snapshot", cfg.SaveSnapshot, "")
	fs.StringVar(&cfg.DiffFrom, "diff", cfg.DiffFrom, "")
	fs.StringVar(&cfg.BaselineFile, "baseline", cfg.BaselineFile, "")
	fs.StringVar(&cfg.FailOn, "fail-on", cfg.FailOn, "")
	fs.Var(&maxIssues, "max-issues", "")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "")
	fs.Float64Var(&cfg.QPS, "qps", cfg.QPS, "")
	fs.IntVar(&cfg.Burst, "burst", cfg.Burst, "")
	fs.Int64Var(&cfg.PageSize, "page-size", cfg.PageSize, "")
	fs.StringVar(&cfg.HistoryDB, "history-db", cfg.HistoryDB, "")
	fs.IntVar(&cfg.HistoryWindow, "history-window", cfg.HistoryWindow, "")
	fs.IntVar(&cfg.FlapThreshold, "flap-threshold", cfg.FlapThreshold, "")
	fs.IntVar(&cfg.RestartGrowth, "restart-growth", cfg.RestartGrowth, "")
	fs.IntVar(&cfg.HistoryRetain, "history-retain", cfg.HistoryRetain, "")
	fs.StringVar(&cfg.WebhookURLEnv, "webhook-url-env", cfg.WebhookURLEnv, "")
	fs.StringVar(&cfg.WebhookFormat, "webhook-format", cfg.WebhookFormat, "")
	fs.IntVar(&cfg.WebhookTimeout, "webhook-timeout", cfg.WebhookTimeout, "")
	fs.BoolVar(&cfg.Version, "version", false, "")
	var help bool
	fs.BoolVar(&help, "h", false, "")
	fs.BoolVar(&help, "help", false, "")
	if err := fs.Parse(args); err != nil {
		return cfg, fmt.Errorf("引数を解析できません: %w", err)
	}
	if fs.NArg() != 0 {
		return cfg, fmt.Errorf("位置引数は使用できません: %s", strings.Join(fs.Args(), " "))
	}
	if help {
		return cfg, ErrHelp
	}
	selected := 0
	for _, value := range []bool{all, selectMode, list, triage} {
		if value {
			selected++
		}
	}
	if selected > 1 {
		return cfg, errors.New("診断モードは -a、-s、--list、--triage のいずれか1つだけ指定してください")
	}
	if commandMode(command) != "" && selected > 0 {
		return cfg, fmt.Errorf("%s コマンドでは診断モードを追加指定できません", command)
	}
	if all {
		cfg.Mode = "all"
	} else if selectMode {
		cfg.Mode = "select"
	} else if list {
		cfg.Mode = "list"
	} else if triage {
		cfg.Mode = "triage"
	}
	if noMask {
		cfg.Mask = false
	}
	if showCmd && noCmd {
		return cfg, errors.New("--cmd と --no-cmd は同時に指定できません")
	}
	if showCmd {
		cfg.ShowCmd = true
	}
	if noCmd {
		cfg.ShowCmd = false
	}
	if (showCmd || noCmd) && !showAPIRequests && !noAPIRequests && !cfg.SettingExplicit("display.show_api_requests") {
		// Before show_api_requests existed, --cmd/--no-cmd controlled both
		// kubectl hints and the API trace. Preserve that behaviour unless the
		// new setting is explicitly configured.
		cfg.ShowAPIRequests = cfg.ShowCmd
	}
	if showAPIRequests && noAPIRequests {
		return cfg, errors.New("--api-requests と --no-api-requests は同時に指定できません")
	}
	if showAPIRequests {
		cfg.ShowAPIRequests = true
	}
	if noAPIRequests {
		cfg.ShowAPIRequests = false
	}
	if maxIssues.set {
		value := maxIssues.value
		cfg.MaxIssues = &value
	}
	if err := cfg.Validate(args); err != nil {
		return cfg, err
	}
	return cfg, nil
}

var ErrHelp = errors.New("help requested")

type optionalInt struct {
	set   bool
	value int
}

func (o *optionalInt) String() string {
	if !o.set {
		return ""
	}
	return strconv.Itoa(o.value)
}

func (o *optionalInt) Set(value string) error {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return errors.New("0以上の整数で指定してください")
	}
	o.set, o.value = true, n
	return nil
}

var namespaceRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var envRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (c Config) Validate(raw []string) error {
	if c.Version {
		return nil
	}
	if c.Namespace != "" && !namespaceRE.MatchString(c.Namespace) {
		return fmt.Errorf("Namespace名が不正です: %s", c.Namespace)
	}
	for label, value := range map[string]int{
		"--timeout": c.RequestTimeout, "--events-limit": c.EventsLimit,
		"--tail": c.Tail, "--log-signature-lines": c.LogSignatureLines,
		"--node-heartbeat-timeout": c.NodeHeartbeatTimeout,
		"--workers":                c.Workers, "--burst": c.Burst, "--history-window": c.HistoryWindow,
		"--flap-threshold": c.FlapThreshold, "--restart-growth": c.RestartGrowth,
		"--history-retain": c.HistoryRetain, "--webhook-timeout": c.WebhookTimeout,
	} {
		if value < 1 {
			return fmt.Errorf("%s は1以上の整数で指定してください", label)
		}
	}
	if c.Workers > 16 {
		return errors.New("--workers は1以上16以下で指定してください")
	}
	if c.LogSignatureLines > 5000 {
		return errors.New("--log-signature-lines は5000以下で指定してください")
	}
	if c.RestartThreshold < 0 {
		return errors.New("--restart-threshold は0以上で指定してください")
	}
	if c.Watch < 0 || c.explicitlyConfigured(raw, "diagnosis.watch", "-w", "--watch") && c.Watch == 0 {
		return errors.New("--watch は1以上の整数で指定してください")
	}
	if c.ConnectPort != 0 && (c.ConnectPort < 1024 || c.ConnectPort > 65535) {
		return errors.New("--connect-port は1024以上65535以下で指定してください")
	}
	if c.ConnectPath != "" {
		if !strings.HasPrefix(c.ConnectPath, "/") || strings.ContainsAny(c.ConnectPath, " \t\r\n") {
			return errors.New("--connect-path は、空白を含まず「/」で始まる値を指定してください（例: /ready）")
		}
	}
	if c.ConnectPort != 0 && !c.Connect || c.ConnectPath != "" && !c.Connect {
		return errors.New("--connect-port または --connect-path を使用するには、--connect も指定してください")
	}
	if c.Connect && c.Mode != "select" {
		return errors.New("--connect は個別診断（-s）でのみ使用できます")
	}
	if c.Debug && c.Mode != "all" && c.Mode != "select" {
		return errors.New("--debug は -a または -s と組み合わせてください")
	}
	if c.Debug && c.Output != "text" {
		return errors.New("--debug は対話形式のテキスト出力（--output=text）でのみ使用できます")
	}
	if c.Debug && (strings.TrimSpace(c.DebugImage) == "" || strings.ContainsAny(c.DebugImage, " \t\r\n")) {
		return errors.New("--debug-image には、空ではなく空白を含まないコンテナイメージを指定してください")
	}
	if c.Debug && (strings.TrimSpace(c.DebugProfile) == "" || strings.ContainsAny(c.DebugProfile, " \t\r\n")) {
		return errors.New("--debug-profile には、空ではなく空白を含まないプロファイル名を指定してください")
	}
	if (c.explicitlyConfigured(raw, "debug.image", "--debug-image") || c.explicitlyConfigured(raw, "debug.profile", "--debug-profile")) && !c.Debug {
		return errors.New("--debug-image または --debug-profile を使用するには、--debug も指定してください")
	}
	if c.Watch > 0 && c.Mode != "all" && c.Mode != "triage" {
		return errors.New("--watch は -a または --triage と組み合わせてください")
	}
	if c.Watch > 0 && c.Debug {
		return errors.New("--debug と --watch は併用できません")
	}
	if c.ShowLogs && c.Mode != "all" {
		return errors.New("--logs は全体診断（-a）でのみ使用できます")
	}
	if c.ShowUnused && c.Mode != "all" {
		return errors.New("--unused は全体診断（-a）でのみ使用できます")
	}
	logDiagnosis := c.Mode == "select" || c.Mode == "all" && c.ShowLogs
	if (c.LogSignatures != "" || c.explicitlyConfigured(raw, "diagnosis.log_signature_lines", "--log-signature-lines")) && !logDiagnosis {
		return errors.New("--log-signatures または --log-signature-lines は、-s または「-a --logs」と組み合わせてください")
	}
	if c.explicitlyConfigured(raw, "display.tail", "--tail") && !logDiagnosis {
		return errors.New("--tail は、-s または「-a --logs」と組み合わせてください")
	}
	if c.Mode == "list" && c.explicitlyConfigured(raw, "diagnosis.events_limit", "--events-limit") {
		return errors.New("--events-limit は --list では使用できません")
	}
	if c.Mode == "list" && c.explicitlyConfigured(raw, "diagnosis.restart_threshold", "--restart-threshold") {
		return errors.New("--restart-threshold は --list では使用できません")
	}
	if c.Mode != "all" && c.Mode != "triage" && c.explicitlyConfigured(raw, "diagnosis.node_heartbeat_timeout", "--node-heartbeat-timeout") {
		return errors.New("--node-heartbeat-timeout は -a または --triage と組み合わせてください")
	}
	if c.Mode == "list" && c.BaselineFile != "" {
		return errors.New("--baseline は -a、-s、--triage のいずれかと組み合わせてください")
	}
	if c.Mode == "list" && c.explicitlyConfigured(raw, "display.exit_zero", "--exit-zero") {
		return errors.New("--exit-zero は --list では使用しても結果が変わりません")
	}
	structured := c.Output != "text"
	if !oneOf(c.Output, "text", "json", "sarif", "junit", "mermaid", "dot") {
		return errors.New("--output は text、json、sarif、junit、mermaid、dot のいずれかを指定してください")
	}
	if structured && !c.Mask {
		return errors.New("--no-mask または display.mask_secrets=false は、テキスト出力でのみ使用できます")
	}
	if structured && c.explicitlyConfigured(raw, "display.show_commands", "--cmd", "--no-cmd") {
		return errors.New("--cmd または --no-cmd は、テキスト出力でのみ使用できます")
	}
	if structured && c.explicitlyConfigured(raw, "display.show_api_requests", "--api-requests", "--no-api-requests") {
		return errors.New("--api-requests または --no-api-requests は、テキスト出力でのみ使用できます")
	}
	if structured && c.explicitlyConfigured(raw, "display.tail", "--tail") {
		return errors.New("--tail は、テキスト出力でのみ使用できます")
	}
	if structured && c.explicitlyConfigured(raw, "diagnosis.events_limit", "--events-limit") {
		return errors.New("--events-limit は、テキスト出力でのみ使用できます")
	}
	if structured && c.Mode != "all" && c.Mode != "triage" {
		return errors.New("--output に text 以外の形式を指定できるのは、-a または --triage の場合だけです")
	}
	if structured && c.Watch > 0 {
		return errors.New("--output に text 以外の形式を指定した場合、--watch は併用できません")
	}
	if c.OutputFile != "" && !structured {
		return errors.New("--output-file を使用するには、--output に text 以外の形式を指定してください")
	}
	if err := validateDistinctOutputPaths(c); err != nil {
		return err
	}
	if (c.SaveSnapshot != "" || c.DiffFrom != "") && c.Mode != "all" && c.Mode != "triage" {
		return errors.New("--save-snapshot または --diff は、-a または --triage と組み合わせてください")
	}
	if (c.SaveSnapshot != "" || c.DiffFrom != "") && c.Watch > 0 {
		return errors.New("--save-snapshot または --diff と、--watch は併用できません")
	}
	if !oneOf(c.FailOn, "issue", "warning", "unavailable", "any", "none") {
		return errors.New("--fail-on は issue、warning、unavailable、any、none のいずれかを指定してください")
	}
	failPolicyConfigured := c.explicitlyConfigured(raw, "report.fail_on", "--fail-on") || c.explicitlyConfigured(raw, "report.max_issues", "--max-issues")
	if failPolicyConfigured && c.Mode != "all" && c.Mode != "triage" {
		return errors.New("--fail-on または --max-issues は、-a または --triage と組み合わせてください")
	}
	if c.FailOn == "none" && c.MaxIssues != nil {
		return errors.New("--fail-on=none を指定した場合、--max-issues は使用しても結果が変わりません")
	}
	if c.ExitZero && failPolicyConfigured {
		return errors.New("--exit-zero は、--fail-on または --max-issues と併用できません")
	}
	if c.Watch > 0 && (c.ExitZero || failPolicyConfigured) {
		return errors.New("--watch と、--exit-zero、--fail-on、--max-issues は併用できません")
	}
	if c.HistoryDB != "" && c.Mode != "all" && c.Mode != "triage" {
		return errors.New("--history-db は -a または --triage と組み合わせてください")
	}
	if c.HistoryWindow < 2 || c.FlapThreshold >= c.HistoryWindow {
		return errors.New("--history-window は2以上、--flap-threshold は --history-window 未満で指定してください")
	}
	if c.WebhookURLEnv != "" {
		if !envRE.MatchString(c.WebhookURLEnv) {
			return errors.New("--webhook-url-env には、有効な環境変数名を指定してください")
		}
		if c.DiffFrom == "" && c.HistoryDB == "" && c.Watch == 0 {
			return errors.New("--webhook-url-env を使用するには、--diff、--history-db、--watch のいずれかも指定してください")
		}
	}
	if c.WebhookURLEnv == "" && (c.explicitlyConfigured(raw, "notification.format", "--webhook-format") || c.explicitlyConfigured(raw, "notification.timeout", "--webhook-timeout")) {
		return errors.New("--webhook-format または --webhook-timeout を使用するには、--webhook-url-env も指定してください")
	}
	if !oneOf(c.WebhookFormat, "generic", "slack") {
		return errors.New("--webhook-format は generic または slack を指定してください")
	}
	if c.HistoryDB == "" && c.Watch == 0 && (c.explicitlyConfigured(raw, "history.window", "--history-window") || c.explicitlyConfigured(raw, "history.flap_threshold", "--flap-threshold") || c.explicitlyConfigured(raw, "history.restart_growth", "--restart-growth")) {
		return errors.New("--history-window、--flap-threshold、--restart-growth を使用するには、--history-db または --watch も指定してください")
	}
	if c.HistoryDB == "" && c.explicitlyConfigured(raw, "history.retain", "--history-retain") {
		return errors.New("--history-retain を使用するには、--history-db も指定してください")
	}
	if c.PageSize < 1 || c.PageSize > 5000 {
		return errors.New("--page-size は1以上5000以下で指定してください")
	}
	if c.QPS <= 0 || math.IsNaN(c.QPS) || math.IsInf(c.QPS, 0) || c.QPS > math.MaxFloat32 || float32(c.QPS) == 0 {
		return errors.New("--qps には、0より大きくfloat32で表現可能な有限値を指定してください")
	}
	return nil
}

type configuredPath struct {
	label      string
	value      string
	expandHome bool
}

func validateDistinctOutputPaths(c Config) error {
	writers := []configuredPath{
		{"--output-file", c.OutputFile, false},
		{"--save-snapshot", c.SaveSnapshot, false},
		{"--history-db", c.HistoryDB, true},
	}
	readers := []configuredPath{
		{"--config", c.ConfigFile, false},
		{"--diff", c.DiffFrom, false},
		{"--baseline", c.BaselineFile, false},
		{"--log-signatures", c.LogSignatures, false},
		{"--kubeconfig", c.Kubeconfig, false},
	}
	for left := 0; left < len(writers); left++ {
		if writers[left].value == "" {
			continue
		}
		for right := left + 1; right < len(writers); right++ {
			if writers[right].value == "" {
				continue
			}
			same, err := sameConfiguredPath(writers[left], writers[right])
			if err != nil {
				return fmt.Errorf("出力先パスを検証できません: %w", err)
			}
			if same {
				return fmt.Errorf("%s と %s に同じファイルを指定できません", writers[left].label, writers[right].label)
			}
		}
		for _, reader := range readers {
			if reader.value == "" {
				continue
			}
			same, err := sameConfiguredPath(writers[left], reader)
			if err != nil {
				return fmt.Errorf("入出力パスを検証できません: %w", err)
			}
			if same {
				return fmt.Errorf("%s の出力先には、入力ファイルとして使用している %s を指定できません", writers[left].label, reader.label)
			}
		}
	}
	return nil
}

func sameConfiguredPath(left, right configuredPath) (bool, error) {
	leftPath, err := canonicalConfiguredPath(left.value, left.expandHome)
	if err != nil {
		return false, err
	}
	rightPath, err := canonicalConfiguredPath(right.value, right.expandHome)
	if err != nil {
		return false, err
	}
	if leftPath == rightPath {
		return true, nil
	}
	leftInfo, leftErr := os.Stat(leftPath)
	rightInfo, rightErr := os.Stat(rightPath)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo), nil
}

func canonicalConfiguredPath(value string, expandHome bool) (string, error) {
	if expandHome && (value == "~" || strings.HasPrefix(value, "~/")) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		return resolved, nil
	}
	parent := filepath.Dir(absolute)
	if resolvedParent, err := filepath.EvalSymlinks(parent); err == nil {
		return filepath.Join(resolvedParent, filepath.Base(absolute)), nil
	}
	return filepath.Clean(absolute), nil
}

func optionPresent(args []string, names ...string) bool {
	for _, arg := range args {
		name := strings.SplitN(arg, "=", 2)[0]
		for _, candidate := range names {
			if name == candidate {
				return true
			}
		}
	}
	return false
}

func booleanOptionEnabled(args []string, names ...string) (bool, error) {
	value := false
	for _, arg := range args {
		name, raw, hasValue := arg, "", false
		if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			name, raw, hasValue = parts[0], parts[1], true
		}
		matched := false
		for _, candidate := range names {
			if name == candidate {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if !hasValue {
			value = true
			continue
		}
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return false, fmt.Errorf("%s の真偽値が不正です: %q", name, raw)
		}
		value = parsed
	}
	return value, nil
}

func (c Config) explicitlyConfigured(args []string, setting string, names ...string) bool {
	return optionPresent(args, names...) || c.explicitSettings[setting]
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func findConfigPath(args []string) (string, error) {
	path := ""
	for index := 0; index < len(args); index++ {
		arg := args[index]
		value := ""
		if strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config=") {
			value = strings.TrimSpace(strings.SplitN(arg, "=", 2)[1])
		} else if arg == "--config" || arg == "-config" {
			if index+1 >= len(args) || strings.TrimSpace(args[index+1]) == "" {
				return "", errors.New("--config には空ではないファイルパスを指定してください")
			}
			index++
			value = strings.TrimSpace(args[index])
		} else {
			continue
		}
		if value == "" {
			return "", errors.New("--config には空ではないファイルパスを指定してください")
		}
		if path != "" {
			return "", errors.New("--config は1回だけ指定してください")
		}
		path = value
	}
	return path, nil
}

func Help(prog string) string {
	return HelpStyled(prog, false)
}

// HelpStyled returns the complete user-facing help.  Keeping the plain and
// coloured variants on one source string prevents options documented in one
// view from silently disappearing from the other.
func HelpStyled(prog string, color bool) string {
	plain := fmt.Sprintf(`%s — Kubernetesクラスタ診断 / CI対応 (Go版)

使い方:
  %s [診断モード] [対象] [追加オプション]

診断モード (同時に1つ、未指定時は-a):
  -a, --all                 クラスタ全体を診断
  -s, --select              Namespace/Pod名で絞り、上下矢印＋Enterで個別診断
  -p, --list, --pods        Pod一覧とヘルスサマリのみ
      --triage              確定異常を短時間で集約

Pod選択操作 (-s / -a --debug):
  ↑ / ↓                    Podを移動
  Enter / →                 選択したPodを決定
  n                         一覧を表示したままNamespace検索を編集
  / または f                一覧を表示したままPod名検索を編集
  r                         Namespace・Pod名検索を続けて編集
  c                         検索条件を消去
  b                         1つ前へ戻る
  q                         選択画面を終了
  選択画面は決定・終了時に消去し、元の端末画面へ戻ります。

対象・API設定:
      --config FILE         INI設定ファイル (CLI指定が優先、-configも受理)
      --no-config           ./k8s-diagnose.iniの自動読込を無効化
  -n, --namespace NAME      対象namespace (省略時は全namespace)
      --context NAME        kubeconfig context
      --kubeconfig FILE     kubeconfigファイル
      --timeout SEC         API要求タイムアウト (既定15)
      --workers N           並列取得数 1〜16 (既定4)
      --qps N               client-go QPS (既定10)
      --burst N             client-go Burst (既定20)
      --page-size N         List APIページサイズ (既定500)

追加診断:
      --logs                失敗Podのログ (-aのみ)
      --unused              未使用候補 (-aのみ)
      --log-signatures FILE ログシグネチャINI (-s / -a --logs)
      --log-signature-lines N 解析するログ末尾行数 1〜5000 (既定200)
      --events-limit N      最新イベント数 (既定20)
      --restart-threshold N 再起動警告閾値 (既定5)
      --node-heartbeat-timeout SEC Node Lease停滞判定 (既定180)
      --connect             一時port-forwardで単発確認 (-sのみ・追加確認なし)
      --connect-port PORT   ローカル先頭ポート 1024〜65535
      --connect-path PATH   /で始まるHTTPパス
      --debug               診断後にdebugメニュー (-a / -s)
      --debug-image IMAGE   debug用image (既定busybox:1.36)
      --debug-profile NAME  kubectl debug profile (既定general)

表示・CI:
      --tail N              ログ表示行数 (既定30)
      --no-mask             対話端末のtext表示だけ秘匿情報マスクを無効化
  -w, --watch SEC           1秒以上の間隔で再診断 (-a / --triage)
      --cmd / --no-cmd      各診断項目の確認用kubectlの表示切替
      --api-requests / --no-api-requests
                            末尾の「実行したKubernetes API要求」の表示切替
      --exit-zero           所見があってもexit 0
      --output FORMAT       text/json/sarif/junit/mermaid/dot
      --output-file FILE    構造化出力の保存先
      --save-snapshot FILE  今回の結果を保存
      --diff FILE           前回snapshotと比較
      --baseline FILE       期限・理由付き承認済み所見INI
      --fail-on LEVEL       issue/warning/unavailable/any/none
      --max-issues N        fail-on対象の許容件数

履歴・通知:
      --history-db FILE       SQLite履歴
      --history-window N      分析回数 (既定12)
      --flap-threshold N      フラッピング遷移数 (既定3)
      --restart-growth N      restartCount増加閾値 (既定3)
      --history-retain N      保持実行数 (既定1000)
      --webhook-url-env NAME  HTTPS URLを保持する環境変数
      --webhook-format TYPE   generic/slack
      --webhook-timeout SEC   送信タイムアウト
      --version               バージョンを表示
  -h, --help                  このヘルプを表示

組み合わせの要点:
  --logs / --unused          -aのみ
  --tail / --log-signatures  -s、または-a --logs
  --connect                  -sのみ
  --connect-port/path        -s --connectが必要
  --debug-image/profile      -a/-s --debugが必要
  --watch                    -a / --triageのみ
  --node-heartbeat-timeout   -a / --triageのみ
  --baseline / --exit-zero   --listでは使用不可
  --events/restart-threshold --listでは使用不可
  --fail-on / --max-issues   -a / --triageのみ
  --exit-zero                --watch / --fail-on / --max-issuesと併用不可
  --fail-on none             --max-issuesと併用不可
  --watch                    --fail-on / --max-issuesと併用不可
  --no-mask/cmd/tail/events  text出力のみ
  text以外の --output       -a / --triageのみ、--watchとの併用不可
  --history-db               -a / --triageのみ、--watch可
  --webhook-url-env          --diff / --history-db / --watchのいずれかが必要
  --webhook-format/timeout   --webhook-url-envが必要
  --history-window/flap/restart-growth  --history-dbまたは--watchが必要
  --history-retain           --history-dbが必要

終了コード:
  0   CI失敗条件内、選択画面の正常終了、または--exit-zero
  1   CI失敗条件超過、引数/API/出力/通知エラー
  130 Ctrl-Cによる中断 (--watch中は0)

例:
  %s -a --logs --unused
  %s -s --connect --connect-path /ready
  %s --triage --output json --output-file result.json
  %s -a --save-snapshot before.json
  %s -a --diff before.json --fail-on warning
  %s --config ./k8s-diagnose.ini
`, prog, prog, prog, prog, prog, prog, prog, prog)
	return colorizeHelp(plain, prog, color)
}

func colorizeHelp(plain, prog string, color bool) string {
	if !color {
		return plain
	}
	const (
		cyan   = "\x1b[1;36m"
		blue   = "\x1b[1;34m"
		green  = "\x1b[1;32m"
		yellow = "\x1b[1;33m"
		reset  = "\x1b[0m"
	)
	lines := strings.Split(plain, "\n")
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case index == 0:
			lines[index] = cyan + line + reset
		case line == trimmed && strings.HasSuffix(line, ":"):
			lines[index] = blue + line + reset
		case strings.HasPrefix(line, "  "+prog):
			lines[index] = green + line + reset
		case strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "-"):
			lines[index] = yellow + line + reset
		}
	}
	return strings.Join(lines, "\n")
}

func PrintError(stream io.Writer, prog string, err error) {
	message := redact.MaskSecrets(err.Error())
	program := redact.SanitizeText(prog)
	fmt.Fprintf(stream, "エラー: %s\n使い方は '%s --help'、全フラグと組み合わせは '%s advanced --help' で確認できます。\n", message, program, program)
}

func EnsureReadableFile(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("指定されたパスは通常ファイルではありません")
	}
	return nil
}
