package redact

import (
	"strings"
	"testing"
)

func TestMaskSecretsCoversPersistentOutputPatterns(t *testing.T) {
	privateKey := "-----BEGIN PRIVATE KEY-----\nvery-secret-key-material\n-----END PRIVATE KEY-----"
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
	input := strings.Join([]string{
		`password="two words" trailing=safe`,
		`authorization=Basic dXNlcjpwYXNzd29yZA==`,
		`Authorization: Bearer visible-token`,
		`Cookie: session=browser-secret; csrf=csrf-secret`,
		`Set-Cookie=auth=response-secret; Secure`,
		`password="escaped\"quote-secret" trailing-escaped=safe`,
		`{"password":"json-secret","nested":{"api_key":"api-secret"}}`,
		`DB_PASSWORD=database-secret`,
		`aws_secret_access_key=aws-secret`,
		`postgres://user:database-secret@db.example/app`,
		jwt,
		privateKey,
		`ghp_abcdefghijklmnopqrstuvwxyz123456`,
	}, "\n")
	masked := MaskSecrets(input)
	for _, secret := range []string{
		"two words", "dXNlcjpwYXNzd29yZA==", "visible-token", "json-secret", "api-secret",
		"database-secret", "aws-secret", "browser-secret", "csrf-secret", "response-secret", "quote-secret",
		jwt, "very-secret-key-material", "ghp_abcdefghijklmnopqrstuvwxyz123456",
	} {
		if strings.Contains(masked, secret) {
			t.Fatalf("秘匿値 %q が残った: %s", secret, masked)
		}
	}
	for _, marker := range []string{"<masked>", "<masked-jwt>", "<masked-private-key>", "<masked-token>"} {
		if !strings.Contains(masked, marker) {
			t.Fatalf("マスク結果に%sがない: %s", marker, masked)
		}
	}
	if !strings.Contains(masked, "trailing=safe") || !strings.Contains(masked, "postgres://user:<masked>@db.example/app") {
		t.Fatalf("安全な文脈まで失われた: %s", masked)
	}
}

// TestMaskSecretsCoversPreDistributionLeaks pins the exact forms that slipped
// through before the Phase 0-1 redaction fix. Each entry is a form that a real
// diagnostic report, snapshot or notification could carry to Slack or a ticket.
func TestMaskSecretsCoversPreDistributionLeaks(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		secret string
	}{
		{"json-quoted-authorization", `{"Authorization":"auth-secret-value"}`, "auth-secret-value"},
		{"json-quoted-cookie", `{"Cookie":"session=cookie-secret"}`, "cookie-secret"},
		{"json-quoted-set-cookie", `{"Set-Cookie":"auth=setcookie-secret"}`, "setcookie-secret"},
		{"private-key-assignment", `private_key=pk-secret-value`, "pk-secret-value"},
		{"json-quoted-private-key", `{"private_key":"pk-json-secret"}`, "pk-json-secret"},
		{"encryption-key-assignment", `encryption_key=ek-secret-value`, "ek-secret-value"},
		{"json-quoted-encryption-key", `{"encryptionKey":"ek-json-secret"}`, "ek-json-secret"},
		{"unquoted-value-with-spaces", `password=first-word second-secret`, "second-secret"},
		{"unquoted-token-with-spaces", `api_key=abc def ghi-secret`, "ghi-secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			masked := MaskSecrets(tc.input)
			if strings.Contains(masked, tc.secret) {
				t.Fatalf("秘匿値 %q が残った: %s", tc.secret, masked)
			}
			if !strings.Contains(masked, "<masked>") {
				t.Fatalf("マスクマーカーが無い: %s", masked)
			}
		})
	}
}

// TestMaskSecretsCoversVendorTokenFormats covers credentials that appear
// without a key name — pasted into a log line or an event message — where only
// the vendor prefix identifies them.
func TestMaskSecretsCoversVendorTokenFormats(t *testing.T) {
	tokens := map[string]string{
		"aws-access-key":    "AKIAIOSFODNN7EXAMPLE",
		"aws-temporary-key": "ASIAIOSFODNN7EXAMPLE",
		"github-pat":        "ghp_abcdefghijklmnopqrstuvwxyz123456",
		"slack-bot":         "xoxb-1234567890-abcdefghij",
		"google-api-key":    "AIzaSyD-1234567890abcdefghijklmnopqrstu",
		"stripe-live":       "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		"stripe-restricted": "rk_test_4eC39HqLyjWDarjtT1zdp7dc",
		"twilio-sid":        "AC0123456789abcdef0123456789abcdef",
		"sendgrid":          "SG.aBcDeFgHiJkLmNoP.qRsTuVwXyZ0123456789abcd",
	}
	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			masked := MaskSecrets("kubelet log: credential " + token + " rejected")
			if strings.Contains(masked, token) {
				t.Fatalf("ベンダートークンが残った: %s", masked)
			}
			if !strings.Contains(masked, "rejected") {
				t.Fatalf("周囲の文脈まで失われた: %s", masked)
			}
		})
	}
}

func TestMaskSecretsDoesNotMaskOrdinaryDiagnosticText(t *testing.T) {
	// Over-masking is the intended failure mode for key=value pairs, but plain
	// diagnostic prose must survive or the tool stops being readable.
	for _, safe := range []string{
		"Pod prod/api is in CrashLoopBackOff",
		"ACCOUNT balance check failed",
		"image example/api:1.2.3 not found",
		"node-1 NotReady",
	} {
		if masked := MaskSecrets(safe); masked != safe {
			t.Errorf("通常の診断文がマスクされた: %q -> %q", safe, masked)
		}
	}
}

func TestMaskSecretsPreservesTrailingContextForQuotedValues(t *testing.T) {
	// A quoted value must be masked precisely so the following safe context
	// survives; only unquoted values are widened to end of line.
	masked := MaskSecrets(`{"password":"json-secret","namespace":"prod"}`)
	if strings.Contains(masked, "json-secret") {
		t.Fatalf("秘匿値が残った: %s", masked)
	}
	if !strings.Contains(masked, `"namespace":"prod"`) {
		t.Fatalf("引用符付き値のマスクで後続の安全な文脈まで失われた: %s", masked)
	}
}

func TestMaskSecretsCoversPEMPrivateKeyVariants(t *testing.T) {
	for _, kind := range []string{"DSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY"} {
		value := "-----BEGIN " + kind + "-----\nsecret-material\n-----END " + kind + "-----"
		masked := MaskSecrets(value)
		if strings.Contains(masked, "secret-material") || masked != "<masked-private-key>" {
			t.Fatalf("%sをマスクできない: %s", kind, masked)
		}
	}
}

func TestSensitiveStructuredKeys(t *testing.T) {
	for _, key := range []string{"password", "DB_PASSWORD", "authorization", "aws_secret_access_key", "private-key", "private_key", "encryption_key", "cookie", "set-cookie", "session_token"} {
		if !IsSensitiveKey(key) {
			t.Errorf("機密キーを検出できない: %s", key)
		}
	}
	for _, key := range []string{"namespace", "resource", "container_name", "monkey"} {
		if IsSensitiveKey(key) {
			t.Errorf("通常キーを機密扱いした: %s", key)
		}
	}
}

func TestSanitizeTextRemovesTerminalAndBidiControls(t *testing.T) {
	input := "before\x1b]52;c;payload\a\r\b\u202eafter\nnext\tcolumn"
	got := SanitizeText(input)
	if strings.ContainsAny(got, "\x1b\a\r\b\u202e") {
		t.Fatalf("危険な制御文字が残った: %q", got)
	}
	if got != "before]52;c;payloadafter\nnext\tcolumn" {
		t.Fatalf("通常文字または許可した改行/タブまで変化した: %q", got)
	}
}
