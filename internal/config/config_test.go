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
	} {
		if _, err := Parse(args, "k8s-diagnose"); err == nil {
			t.Fatalf("構造化出力で意味を持たない指定が受理された: %v", args)
		}
	}
	if _, err := Parse([]string{"--help"}, "k8s-diagnose"); !errors.Is(err, ErrHelp) {
		t.Fatalf("--helpの結果=%v", err)
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
