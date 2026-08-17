package config

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzLoadINI(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(""),
		[]byte("[target]\nnamespace = production\n"),
		[]byte("[diagnosis]\nmode = triage\nworkers = 4\n"),
		[]byte("[unknown]\nvalue = secret\n"),
		[]byte("[target]\nnamespace = one\nnamespace = two\n"),
		// Quoting and escaping drive splitQuotedINIValue -> strconv.Unquote,
		// which is the fiddliest part of the parser.
		[]byte(`[target]` + "\n" + `namespace = "quoted"` + "\n"),
		[]byte(`[target]` + "\n" + `namespace = "unterminated` + "\n"),
		[]byte(`[target]` + "\n" + `namespace = "esc\"aped" trailing` + "\n"),
		[]byte(`[target]` + "\n" + `namespace = "back\\slash"` + "\n"),
		[]byte(`[target]` + "\n" + `namespace = "" # comment` + "\n"),
		[]byte(`[target]` + "\n" + `namespace = value ; trailing comment` + "\n"),
		[]byte(`[target]` + "\n" + `namespace = "\x"` + "\n"),
		[]byte("[target]\nnamespace = \"\\u00e9\"\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*1024*1024 {
			t.Skip()
		}
		cfg := Defaults()
		_ = loadINI(bytes.NewReader(data), &cfg)
	})
}

// FuzzParseArgs drives the CLI surface. Parse both parses flags and runs
// Validate, so this covers option-combination rules as well as flag decoding.
// The contract asserted here is simple and absolute: for any argument vector,
// Parse either returns an error or returns a Config that Validate accepts. It
// must never panic, and it must never hand back a configuration that its own
// validation would reject.
func FuzzParseArgs(f *testing.F) {
	for _, seed := range []string{
		"",
		"-a",
		"--triage",
		"-s --connect",
		"-a --timeout 0",
		"-a --timeout -1",
		"-a --workers 99",
		"-a --qps NaN",
		"-a --output json --output-file out.json",
		"-a --save-snapshot same.json --diff same.json",
		"-a --load-cluster-snapshot snap.json --logs",
		"-a --save-cluster-snapshot a.json --load-cluster-snapshot b.json",
		"-a --watch 5 --fail-on any",
		"--config /nonexistent.ini",
		"-a --namespace ../escape",
		"-a --connect-port 80",
		"-a --max-issues -3",
		"--version",
		"-h",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		args := strings.Fields(raw)
		if len(args) > 64 {
			t.Skip()
		}
		// Never read a config file from the fuzz corpus: keep the target
		// hermetic and free of filesystem side effects.
		args = append([]string{"--no-config"}, args...)

		cfg, err := Parse(args, "k8s-diagnose")
		if err != nil {
			return
		}
		if err := Validate(cfg); err != nil {
			t.Fatalf("Parseが受理した設定をValidateが拒否した: args=%q err=%v", args, err)
		}
	})
}

// Validate re-runs validation on an already-parsed Config. Parse calls Validate
// internally with the raw arguments; re-validating with no raw arguments must
// not change the verdict, since a Config that parsed cleanly is by definition
// a valid one.
func Validate(cfg Config) error { return cfg.Validate(nil) }
