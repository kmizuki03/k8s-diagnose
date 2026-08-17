package redact

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzMaskSecrets(f *testing.F) {
	for _, seed := range [][2]string{{"", ""}, {"prefix ", " suffix"}, {"\x1b[31m", "\u202e"}, {"日本語", "改行\n後"}, {`{"`, `","k":"v"}`}, {"log: ", " trailing words after value"}} {
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
			// Pre-distribution leak forms that previously slipped through:
			// JSON-quoted keys, keys absent from the old keyValueRE list, and
			// unquoted values containing spaces.
			prefix + `{"Authorization":"` + secret + `"}` + suffix,
			prefix + `{"Cookie":"session=` + secret + `"}` + suffix,
			prefix + "private_key=" + secret + "\n" + suffix,
			prefix + "encryption_key=" + secret + "\n" + suffix,
			prefix + "password=first-word " + secret + "\n" + suffix,
		}
		// Vendor-prefixed tokens carry no key name, so they must be masked on
		// shape alone wherever untrusted text places them.
		for _, token := range []string{
			"AKIAIOSFODNN7EXAMPLE",
			"ASIAIOSFODNN7EXAMPLE",
			"AIzaSyD-1234567890abcdefghijklmnopqrstu",
			"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
			"AC0123456789abcdef0123456789abcdef",
			"SG.aBcDeFgHiJkLmNoP.qRsTuVwXyZ0123456789abcd",
		} {
			if masked := MaskSecrets(prefix + " " + token + " " + suffix); strings.Contains(masked, token) {
				t.Fatalf("ベンダートークンが残った: %q", masked)
			}
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
