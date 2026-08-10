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
	for _, key := range []string{"password", "DB_PASSWORD", "authorization", "aws_secret_access_key", "private-key", "session_token"} {
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
