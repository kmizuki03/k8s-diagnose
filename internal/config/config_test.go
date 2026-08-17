package config

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"port too high", []string{"-s", "--connect", "--connect-port", "70000"}},
		{"path missing slash", []string{"-s", "--connect", "--connect-path", "ready"}},
		{"connect wrong mode", []string{"-a", "--connect"}},
		{"port without connect", []string{"-s", "--connect-port", "18080"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(test.args, "k8s-diagnose"); err == nil {
				t.Fatal("不正な引数が受理された")
			}
		})
	}
	config, err := Parse([]string{"-s", "--connect", "--connect-port", "65535", "--connect-path", "/ready"}, "k8s-diagnose")
	if err != nil || config.ConnectPort != 65535 {
		t.Fatalf("有効な境界値を受理できない: %#v %v", config, err)
	}
}

func TestDistributedExampleConfigIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "k8s-diagnose.ini")
	config, err := Parse([]string{"--config", path}, "k8s-diagnose")
	if err != nil {
		t.Fatalf("配布設定例を読み込めない: %v", err)
	}
	if config.Mode != "all" || config.Workers != 4 || config.Tail != 30 || config.WebhookFormat != "generic" {
		t.Fatalf("空欄で組み込み既定値を維持できていない: %#v", config)
	}
	if _, err := Parse([]string{"--config", path, "--output", "json"}, "k8s-diagnose"); err != nil {
		t.Fatalf("配布設定例を構造化出力へCLI上書きできない: %v", err)
	}
}

func TestPrintErrorSanitizesProgramAndMasksCredentials(t *testing.T) {
	buffer := &bytes.Buffer{}
	PrintError(buffer, "diag\x1b[31m", errors.New("authorization: Basic dXNlcjpwYXNz"))
	got := buffer.String()
	if strings.Contains(got, "\x1b") || strings.Contains(got, "dXNlcjpwYXNz") || !strings.Contains(got, "<masked>") {
		t.Fatalf("CLIエラー出力の安全化が不正: %q", got)
	}
}

func TestINIFailsClosedForUnknownBlankAndDuplicates(t *testing.T) {
	tests := []struct {
		name, body string
	}{
		{"unknown blank", "[target]\nunknown =\n"},
		{"duplicate key", "[target]\nnamespace = prod\nnamespace = staging\n"},
		{"duplicate section", "[target]\nnamespace = prod\n[target]\ncontext = test\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.ini")
			if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := Defaults()
			if err := LoadINI(path, &cfg); err == nil {
				t.Fatalf("曖昧または未知のINIを受理した: %q", test.body)
			}
		})
	}
}

func TestHelpListsEverySpecializedOptionAndSupportsColor(t *testing.T) {
	plain := Help("k8s-diagnose")
	for _, option := range []string{
		"--config", "--log-signature-lines", "--debug-image", "--debug-profile",
		"--webhook-url-env", "--version", "--connect-port/path", "--node-heartbeat-timeout",
		"--no-api-requests",
	} {
		if !strings.Contains(plain, option) {
			t.Fatalf("helpに%sがない", option)
		}
	}
	if strings.Contains(plain, "\x1b[") {
		t.Fatal("非TTY用helpにANSI色が含まれる")
	}
	styled := HelpStyled("k8s-diagnose", true)
	if !strings.Contains(styled, "\x1b[") {
		t.Fatal("TTY用helpにANSI色がない")
	}
}

func TestNodeHeartbeatTimeoutCanBeConfigured(t *testing.T) {
	cfg, err := Parse([]string{"-a", "--node-heartbeat-timeout", "240"}, "k8s-diagnose")
	if err != nil || cfg.NodeHeartbeatTimeout != 240 {
		t.Fatalf("Node heartbeat timeoutを設定できない: %#v %v", cfg, err)
	}
}

func TestModeAndStructuredOutputCombinations(t *testing.T) {
	if _, err := Parse([]string{"-s", "--output", "json"}, "k8s-diagnose"); err == nil {
		t.Fatal("対話モードのJSON出力が許可された")
	}
	if _, err := Parse([]string{"--triage", "--output", "json"}, "k8s-diagnose"); err != nil {
		t.Fatalf("有効な組み合わせが拒否された: %v", err)
	}
	for _, args := range [][]string{
		{"-a", "--logs", "--tail", "50", "--output", "json"},
		{"-a", "--events-limit", "10", "--output", "json"},
		{"-a", "--no-mask", "--output", "json"},
		{"-a", "--no-cmd", "--output", "json"},
		{"-a", "--no-api-requests", "--output", "json"},
	} {
		if _, err := Parse(args, "k8s-diagnose"); err == nil {
			t.Fatalf("構造化出力で意味を持たない指定が受理された: %v", args)
		}
	}
	if _, err := Parse([]string{"--help"}, "k8s-diagnose"); !errors.Is(err, ErrHelp) {
		t.Fatalf("--helpの結果=%v", err)
	}
}

func TestAPIRequestDisplayCanBeControlledIndependently(t *testing.T) {
	cfg, err := Parse([]string{"-a", "--no-api-requests"}, "k8s-diagnose")
	if err != nil || !cfg.ShowCmd || cfg.ShowAPIRequests {
		t.Fatalf("実API要求だけを非表示にできない: cfg=%#v err=%v", cfg, err)
	}

	cfg, err = Parse([]string{"-a", "--no-cmd"}, "k8s-diagnose")
	if err != nil || cfg.ShowCmd || cfg.ShowAPIRequests {
		t.Fatalf("従来の--no-cmd互換で両方を非表示にできない: cfg=%#v err=%v", cfg, err)
	}

	cfg, err = Parse([]string{"-a", "--no-cmd", "--api-requests"}, "k8s-diagnose")
	if err != nil || cfg.ShowCmd || !cfg.ShowAPIRequests {
		t.Fatalf("実API要求を明示指定で独立表示できない: cfg=%#v err=%v", cfg, err)
	}

	if _, err := Parse([]string{"-a", "--api-requests", "--no-api-requests"}, "k8s-diagnose"); err == nil {
		t.Fatal("実API要求の相反する表示指定を受理した")
	}
}

func TestBooleanSettingsExposeSelectionMetadataAndReadableSummary(t *testing.T) {
	var spec SettingSpec
	for _, candidate := range SettingCatalog() {
		if candidate.Name == "display.show_api_requests" {
			spec = candidate
			break
		}
	}
	if !spec.Boolean {
		t.Fatalf("真偽値設定として定義されていない: %#v", spec)
	}
	// The API trace is off by default; the summary must say so and mark it as
	// the built-in value rather than something the operator chose.
	if got := SettingSummary(Defaults(), spec); got != "無効（false）［組み込み既定］" {
		t.Fatalf("既定値の表示=%q", got)
	}
	updated, err := Defaults().WithSetting(spec.Name, "true")
	if err != nil {
		t.Fatal(err)
	}
	if got := SettingSummary(updated, spec); got != "有効（true）" {
		t.Fatalf("明示値の表示=%q", got)
	}
}

func TestAPIRequestINISettingIsOrderIndependentAndBackwardCompatible(t *testing.T) {
	for _, body := range []string{
		"[display]\nshow_commands = false\nshow_api_requests = true\n",
		"[display]\nshow_api_requests = true\nshow_commands = false\n",
	} {
		path := filepath.Join(t.TempDir(), "settings.ini")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Parse([]string{"--config", path}, "k8s-diagnose")
		if err != nil || cfg.ShowCmd || !cfg.ShowAPIRequests {
			t.Fatalf("INI設定順で表示設定が変化した: body=%q cfg=%#v err=%v", body, cfg, err)
		}
	}

	legacyPath := filepath.Join(t.TempDir(), "legacy.ini")
	if err := os.WriteFile(legacyPath, []byte("[display]\nshow_commands = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err := Parse([]string{"--config", legacyPath}, "k8s-diagnose")
	if err != nil || legacy.ShowCmd || legacy.ShowAPIRequests {
		t.Fatalf("旧INIのshow_commands互換を維持できない: cfg=%#v err=%v", legacy, err)
	}

	edited, err := Defaults().WithSetting("display.show_api_requests", "false")
	if err != nil || !edited.ShowCmd || edited.ShowAPIRequests || !edited.SettingExplicit("display.show_api_requests") {
		t.Fatalf("対話設定と共通の設定経路で実API要求を消せない: cfg=%#v err=%v", edited, err)
	}
}

func TestDebugRequiresNonEmptyImageAndProfile(t *testing.T) {
	for _, args := range [][]string{
		{"-a", "--debug", "--debug-image", ""},
		{"-a", "--debug", "--debug-image", "busybox:1.36 bad"},
		{"-a", "--debug", "--debug-profile", ""},
		{"-a", "--debug", "--debug-profile", "general bad"},
	} {
		if _, err := Parse(args, "k8s-diagnose"); err == nil {
			t.Fatalf("kubectl debugで意味を持たない値を受理した: %v", args)
		}
	}
}

func TestWatchAndDependentOptionValidation(t *testing.T) {
	invalid := [][]string{
		{"-a", "--watch", "0"},
		{"-a", "--watch", "-1"},
		{"-a", "--watch", "1", "--exit-zero"},
		{"-a", "--watch", "1", "--fail-on", "warning"},
		{"-a", "--watch", "1", "--max-issues", "2"},
		{"-a", "--exit-zero", "--fail-on", "warning"},
		{"-a", "--exit-zero", "--max-issues", "2"},
		{"-a", "--fail-on", "none", "--max-issues", "0"},
		{"-a", "--webhook-format", "slack"},
		{"-a", "--webhook-timeout", "10"},
		{"-a", "--history-window", "8"},
		{"-a", "--flap-threshold", "2"},
		{"-a", "--restart-growth", "2"},
		{"-a", "--history-retain", "100"},
	}
	for _, args := range invalid {
		if _, err := Parse(args, "k8s-diagnose"); err == nil {
			t.Fatalf("意味を持たない指定が受理された: %v", args)
		}
	}
	valid := [][]string{
		{"-a", "--watch", "1", "--history-window", "8", "--flap-threshold", "2", "--restart-growth", "2"},
		{"-a", "--history-db", "history.db", "--history-retain", "100"},
		{"-a", "--diff", "before.json", "--webhook-url-env", "DIAG_WEBHOOK", "--webhook-format", "slack", "--webhook-timeout", "10"},
	}
	for _, args := range valid {
		if _, err := Parse(args, "k8s-diagnose"); err != nil {
			t.Fatalf("有効な組み合わせが拒否された: %v: %v", args, err)
		}
	}
}

func TestINIDependentOptionsUseTheSameCombinationValidationAsCLI(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"webhook format without URL", "[notification]\nformat = slack\n"},
		{"debug image without debug", "[debug]\nimage = alpine:3\n"},
		{"history window without history", "[history]\nwindow = 8\n"},
		{"tail without log diagnosis", "[diagnosis]\nmode = all\n[display]\ntail = 30\n"},
		{"events limit in list mode", "[diagnosis]\nmode = list\nevents_limit = 10\n"},
		{"restart threshold in list mode", "[diagnosis]\nmode = list\nrestart_threshold = 3\n"},
		{"node heartbeat in select mode", "[diagnosis]\nmode = select\nnode_heartbeat_timeout = 180\n"},
		{"baseline in list mode", "[diagnosis]\nmode = list\n[report]\nbaseline = acknowledged.ini\n"},
		{"exit zero in list mode", "[diagnosis]\nmode = list\n[display]\nexit_zero = true\n"},
		{"fail policy in select mode", "[diagnosis]\nmode = select\n[report]\nfail_on = warning\n"},
		{"fail policy in watch mode", "[diagnosis]\nmode = all\nwatch = 5\n[report]\nfail_on = warning\n"},
		{"exit zero with max issues", "[diagnosis]\nmode = all\n[display]\nexit_zero = true\n[report]\nmax_issues = 1\n"},
		{"max issues with fail none", "[diagnosis]\nmode = all\n[report]\nfail_on = none\nmax_issues = 1\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.ini")
			if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Parse([]string{"--config", path}, "k8s-diagnose"); err == nil {
				t.Fatalf("INIの意味を持たない組み合わせが受理された:\n%s", test.body)
			}
		})
	}

	validPath := filepath.Join(t.TempDir(), "settings.ini")
	valid := "[diagnosis]\nmode = select\n[display]\ntail = 50\n[debug]\nenabled = true\nimage = alpine:3\n"
	if err := os.WriteFile(validPath, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"--config", validPath}, "k8s-diagnose"); err != nil {
		t.Fatalf("有効なINIの依存オプションが拒否された: %v", err)
	}
}

func TestConfigCanOnlyBeSpecifiedOnce(t *testing.T) {
	if _, err := Parse([]string{"--config", "first.ini", "--config=second.ini"}, "k8s-diagnose"); err == nil || !strings.Contains(err.Error(), "1回だけ") {
		t.Fatalf("複数--configを明示的に拒否しない: %v", err)
	}
}

func TestSingleDashConfigLoadsINI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.ini")
	if err := os.WriteFile(path, []byte("[target]\nnamespace = production\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"-config", path}, {"-config=" + path}} {
		cfg, err := Parse(args, "k8s-diagnose")
		if err != nil {
			t.Fatalf("flagパッケージが受理する-config形式を読み込めない: %v", err)
		}
		if cfg.Namespace != "production" || !filepath.IsAbs(cfg.ConfigFile) {
			t.Fatalf("-configのINIが反映されていない: %#v", cfg)
		}
	}
	if _, err := Parse([]string{"-config", path, "--config", path}, "k8s-diagnose"); err == nil || !strings.Contains(err.Error(), "1回だけ") {
		t.Fatalf("異なる表記によるconfig重複を拒否しない: %v", err)
	}
}

func TestQPSRejectsNonFiniteAndFloat32Overflow(t *testing.T) {
	for _, value := range []string{"NaN", "+Inf", "1e100"} {
		if _, err := Parse([]string{"-a", "--qps", value}, "k8s-diagnose"); err == nil {
			t.Fatalf("不正なQPS %qを受理した", value)
		}
	}
	cfg := Defaults()
	cfg.QPS = math.SmallestNonzeroFloat64
	if err := cfg.Validate(nil); err == nil {
		t.Fatal("float32変換で0になるQPSを受理した")
	}
	cfg.QPS = 0.1
	if err := cfg.Validate(nil); err != nil {
		t.Fatalf("通常の正の有限QPSを拒否した: %v", err)
	}
}

// TestPositiveDurationBoundsRejectZero locks in the lower bound for the
// timeout-style options. A zero --timeout would otherwise disable net/http's
// client timeout entirely, turning any unresponsive API server into an
// indefinite hang during incident response.
func TestPositiveDurationBoundsRejectZero(t *testing.T) {
	cases := []struct {
		label string
		set   func(c *Config, v int)
	}{
		{"--timeout", func(c *Config, v int) { c.RequestTimeout = v }},
		{"--webhook-timeout", func(c *Config, v int) { c.WebhookTimeout = v }},
		{"--node-heartbeat-timeout", func(c *Config, v int) { c.NodeHeartbeatTimeout = v }},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			for _, v := range []int{0, -1} {
				cfg := Defaults()
				tc.set(&cfg, v)
				if err := cfg.Validate(nil); err == nil {
					t.Fatalf("%s=%d を受理した", tc.label, v)
				}
			}
		})
	}
}

// TestClusterSnapshotOptionCombinations covers the support workflow flags: a
// replay has no cluster behind it, so anything requiring live access must be
// refused rather than silently doing nothing.
func TestClusterSnapshotOptionCombinations(t *testing.T) {
	rejected := [][]string{
		{"-a", "--save-cluster-snapshot", "a.json", "--load-cluster-snapshot", "b.json"},
		{"-a", "--load-cluster-snapshot", "b.json", "--watch", "5"},
		{"-a", "--load-cluster-snapshot", "b.json", "--logs"},
		{"-a", "--load-cluster-snapshot", "b.json", "--history-db", "history.db"},
		{"-a", "--load-cluster-snapshot", "b.json", "--diff", "previous.json", "--webhook-url-env", "HOOK_URL"},
		{"-a", "--load-cluster-snapshot", "b.json", "--api-requests"},
		{"-l", "--save-cluster-snapshot", "a.json"},
		{"-l", "--load-cluster-snapshot", "b.json"},
		// A replay input must never be clobbered by an output path.
		{"-a", "--load-cluster-snapshot", "same.json", "--save-snapshot", "same.json"},
	}
	for _, args := range rejected {
		if _, err := Parse(args, "k8s-diagnose"); err == nil {
			t.Errorf("不正な組み合わせを受理した: %v", args)
		}
	}
	accepted := [][]string{
		{"-a", "--save-cluster-snapshot", "a.json"},
		{"-a", "--load-cluster-snapshot", "b.json"},
		{"--triage", "--save-cluster-snapshot", "a.json"},
	}
	for _, args := range accepted {
		if _, err := Parse(args, "k8s-diagnose"); err != nil {
			t.Errorf("正当な組み合わせを拒否した: %v (%v)", args, err)
		}
	}
}

func TestOutputDestinationsMustNotCollide(t *testing.T) {
	path := filepath.Join(t.TempDir(), "diagnosis.db")
	if _, err := Parse([]string{"-a", "--output", "json", "--output-file", path, "--save-snapshot", path}, "k8s-diagnose"); err == nil {
		t.Fatal("reportとsnapshotの同一出力先を受理した")
	}
	if _, err := Parse([]string{"-a", "--history-db", path, "--save-snapshot", path}, "k8s-diagnose"); err == nil {
		t.Fatal("SQLite履歴をsnapshotで置換できる指定を受理した")
	}
}

func TestOutputDestinationsMustNotOverwriteInputs(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "settings.ini")
	if err := os.WriteFile(configPath, []byte("[target]\nnamespace = prod\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
	}{
		{"report overwrites config", []string{"--config", configPath, "-a", "--output", "json", "--output-file", configPath}},
		{"snapshot overwrites kubeconfig", []string{"-a", "--kubeconfig", filepath.Join(directory, "cluster.yaml"), "--save-snapshot", filepath.Join(directory, "cluster.yaml")}},
		{"history overwrites diff", []string{"-a", "--history-db", filepath.Join(directory, "before.json"), "--diff", filepath.Join(directory, "before.json")}},
		{"report overwrites baseline", []string{"-a", "--output", "json", "--output-file", filepath.Join(directory, "baseline.ini"), "--baseline", filepath.Join(directory, "baseline.ini")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(test.args, "k8s-diagnose"); err == nil {
				t.Fatalf("入力を上書きする指定を受理した: %v", test.args)
			}
		})
	}
}

func TestOutputInputCollisionDetectsHardLinks(t *testing.T) {
	directory := t.TempDir()
	baselinePath := filepath.Join(directory, "baseline.ini")
	outputPath := filepath.Join(directory, "report.json")
	if err := os.WriteFile(baselinePath, []byte("baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(baselinePath, outputPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"-a", "--output", "json", "--output-file", outputPath, "--baseline", baselinePath}, "k8s-diagnose"); err == nil {
		t.Fatal("hard linkで同一の入力・出力先を受理した")
	}
}

func TestConfigPathInReportRemainsAbsolute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.ini")
	if err := os.WriteFile(path, []byte("[target]\nnamespace = prod\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(workingDirectory, path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]string{"--config", relative}, "k8s-diagnose")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(cfg.ConfigFile) || cfg.ConfigFile != path {
		t.Fatalf("設定ファイルの絶対パスが失われた: got=%q want=%q", cfg.ConfigFile, path)
	}
}

func TestFriendlyCommandsApplyProfilesAndAllowRelevantOverrides(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		check func(Config) bool
	}{
		{"quick", []string{"quick"}, func(c Config) bool {
			return c.Mode == "triage" && c.Output == "text" && c.Mask && !c.ShowCmd && !c.ShowAPIRequests && !c.ExitZero && c.FailOn == "issue" && c.MaxIssues == nil
		}},
		{"ci", []string{"ci"}, func(c Config) bool {
			return c.Mode == "triage" && c.Output == "json" && c.Mask && !c.ShowCmd && !c.ShowAPIRequests && c.FailOn == "issue"
		}},
		{"deep", []string{"deep"}, func(c Config) bool {
			return c.Mode == "all" && c.Output == "text" && c.ShowLogs && c.ShowUnused
		}},
		{"pod", []string{"pod", "--connect", "--connect-path", "/ready"}, func(c Config) bool {
			return c.Mode == "select" && c.Connect && c.ConnectPath == "/ready"
		}},
		{"ci override", []string{"ci", "--output", "sarif", "--output-file", "result.sarif"}, func(c Config) bool {
			return c.Output == "sarif" && c.OutputFile == "result.sarif"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := Parse(test.args, "k8s-diagnose")
			if err != nil {
				t.Fatalf("コマンドを解析できない: %v", err)
			}
			if !test.check(cfg) {
				t.Fatalf("プロファイルまたは上書きが反映されない: %#v", cfg)
			}
		})
	}
	if _, err := Parse([]string{"pod", "--logs"}, "k8s-diagnose"); err == nil {
		t.Fatal("podコマンドでall専用オプションを受理した")
	}
	if _, err := Parse([]string{"all", "-s"}, "k8s-diagnose"); err == nil {
		t.Fatal("固定モードのコマンドへ別モードを追加できた")
	}
}

func TestDeepProfileRetainsLogDetailsThatBecomeRelevant(t *testing.T) {
	cfg, err := ApplyProfile(Defaults(), "pod")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = cfg.WithSetting("display.tail", "77")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = ApplyProfile(cfg, "deep")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ShowLogs || cfg.Tail != 77 {
		t.Fatalf("deepで有効になるログ詳細を失った: %#v", cfg)
	}
}

func TestConfigurationPrecedenceIsINIThenProfileThenCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.ini")
	body := "[target]\nnamespace = production\n[diagnosis]\nmode = all\nwatch = 30\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]string{"quick", "--config", path, "-n", "staging", "--cmd"}, "k8s-diagnose")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Namespace != "staging" || cfg.Mode != "triage" || cfg.Watch != 0 || !cfg.ShowCmd {
		t.Fatalf("INI → profile → CLIの優先順位が不正: %#v", cfg)
	}
}

func TestConfigCommandOnlyAcceptsEditorBootstrapOptions(t *testing.T) {
	if _, err := Parse([]string{"config", "--namespace", "prod"}, "k8s-diagnose"); err == nil || !strings.Contains(err.Error(), "対話画面") {
		t.Fatalf("設定エディタ外の値指定を黙って受理した: %v", err)
	}
	if _, err := Parse([]string{"config", "--no-config"}, "k8s-diagnose"); err != nil {
		t.Fatalf("新規設定編集を拒否した: %v", err)
	}
	newPath := filepath.Join(t.TempDir(), "new-settings.ini")
	cfg, err := Parse([]string{"config", "--config", newPath}, "k8s-diagnose")
	if err != nil || cfg.ConfigFile != newPath {
		t.Fatalf("存在しない保存先を指定した新規設定編集を拒否した: cfg=%#v err=%v", cfg, err)
	}
}

func TestDefaultConfigIsAutomaticallyLoadedAndCanBeDisabled(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, DefaultConfigFilename)
	if err := os.WriteFile(path, []byte("[target]\nnamespace = production\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)
	cfg, err := Parse(nil, "k8s-diagnose")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Namespace != "production" || cfg.ConfigFile != path {
		t.Fatalf("既定INIを自動読込していない: %#v", cfg)
	}
	cfg, err = Parse([]string{"--no-config"}, "k8s-diagnose")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Namespace != "" || cfg.ConfigFile != "" {
		t.Fatalf("--no-configで既定INIを無効化できない: %#v", cfg)
	}
	cfg, err = Parse([]string{"--no-config=false"}, "k8s-diagnose")
	if err != nil || cfg.Namespace != "production" {
		t.Fatalf("false指定で既定INIまで無効化した: cfg=%#v err=%v", cfg, err)
	}
	if _, err := Parse([]string{"--config", path, "--no-config"}, "k8s-diagnose"); err == nil {
		t.Fatal("--configと--no-configを同時に受理した")
	}
}

func TestInteractiveINIRoundTripPreservesQuotedValues(t *testing.T) {
	cfg := Defaults()
	var err error
	cfg, err = cfg.WithSetting("target.context", `team # blue; "primary"`)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path, err := SaveINI(filepath.Join(directory, "saved.ini"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("設定ファイルの権限=%#o, want 0600", info.Mode().Perm())
	}
	loaded, err := Parse([]string{"--config", path}, "k8s-diagnose")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Context != cfg.Context {
		t.Fatalf("引用符付き値が往復で変化した: got=%q want=%q", loaded.Context, cfg.Context)
	}
	malformed := filepath.Join(directory, "malformed.ini")
	if err := os.WriteFile(malformed, []byte("[target]\ncontext = \"unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"--config", malformed}, "k8s-diagnose"); err == nil {
		t.Fatal("閉じていない引用符を受理した")
	}
}

func TestSaveINIRejectsAConfiguredOutputAtTheSettingsPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k8s-diagnose.ini")
	cfg := Defaults()
	var err error
	cfg, err = cfg.WithSetting("report.format", "json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = cfg.WithSetting("report.file", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveINI(path, cfg); err == nil || !strings.Contains(err.Error(), "入力ファイル") {
		t.Fatalf("設定自身をレポート出力先にする内容を保存した: %v", err)
	}
}

func TestINIUnquotedLeadingCommentCharactersRemainBackwardCompatible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.ini")
	if err := os.WriteFile(path, []byte("[target]\ncontext = #local-context\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]string{"--config", path}, "k8s-diagnose")
	if err != nil || cfg.Context != "#local-context" {
		t.Fatalf("従来受理していた先頭#値を変えた: context=%q err=%v", cfg.Context, err)
	}
}

func TestFocusedHelpShowsOnlyTheSelectedEntryPoint(t *testing.T) {
	root := HelpStyledFor("k8s-diagnose", "", false)
	for _, value := range []string{"対話メニュー", "quick", "config", "advanced --help"} {
		if !strings.Contains(root, value) {
			t.Fatalf("入口helpに%qがない: %s", value, root)
		}
	}
	pod := HelpStyledFor("k8s-diagnose", "pod", false)
	if !strings.Contains(pod, "--connect") || strings.Contains(pod, "\n      --unused") {
		t.Fatalf("Pod用helpの段階表示が不正: %s", pod)
	}
	if topic := HelpTopic([]string{"-s", "--help"}); topic != "pod" {
		t.Fatalf("従来モードからhelp topicを解決できない: %q", topic)
	}
}

// The API trace is a debugging aid. Printing it on every run buries the
// diagnosis it exists to support, so it stays off until asked for — and --cmd
// must not switch it back on through the pre-show_api_requests coupling.
func TestAPIRequestTraceIsOffUntilRequested(t *testing.T) {
	if Defaults().ShowAPIRequests {
		t.Fatal("実API要求が既定で表示される")
	}
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"-a"}, false},
		{[]string{"-a", "--cmd"}, false},
		{[]string{"-a", "--api-requests"}, true},
		{[]string{"-a", "--no-cmd"}, false},
	} {
		cfg, err := Parse(tc.args, "k8s-diagnose")
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if cfg.ShowAPIRequests != tc.want {
			t.Errorf("%v: ShowAPIRequests=%v, want %v", tc.args, cfg.ShowAPIRequests, tc.want)
		}
	}
}
