package redact

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzMaskSecrets(f *testing.F) {
	for _, seed := range [][2]string{{"", ""}, {"prefix ", " suffix"}, {"\x1b[31m", "\u202e"}, {"日本語", "改行\n後"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, prefix, suffix string) {
		if len(prefix)+len(suffix) > 128*1024 {
			t.Skip()
		}
		const secret = "K8sDiagnoseFuzzSecret-9f3c1a"
		// The generated context is intentionally untrusted, but the assertion
		// below is about values placed in a secret-bearing field. Prevent a
		// coincidental copy in unrelated context from producing a false failure.
		prefix = strings.ReplaceAll(prefix, secret, "context")
		suffix = strings.ReplaceAll(suffix, secret, "context")
		inputs := []string{
			prefix + ` password="` + secret + `" ` + suffix,
			prefix + "Authorization=Basic " + secret + "\n" + suffix,
			prefix + "https://user:" + secret + "@example.invalid/path " + suffix,
		}
		for _, input := range inputs {
			masked := MaskSecrets(input)
			if strings.Contains(masked, secret) {
				t.Fatalf("既知の秘匿値が残った: %q", masked)
			}
			if !utf8.ValidString(masked) {
				t.Fatalf("マスク結果が不正なUTF-8になった: %q", masked)
			}
			if MaskSecrets(masked) != masked {
				t.Fatalf("マスク処理が冪等でない: first=%q second=%q", masked, MaskSecrets(masked))
			}
		}
	})
}
