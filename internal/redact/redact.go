// Package redact centralizes secret masking for console output, findings,
// reports, snapshots, history and notifications.
package redact

import (
	"regexp"
	"strings"
)

var (
	authorizationRE = regexp.MustCompile(`(?im)(authorization\s*[:=]\s*)([^\r\n]+)`)
	cookieHeaderRE  = regexp.MustCompile(`(?im)^((?:set-)?cookie\s*[:=]\s*)([^\r\n]*)`)
	bearerRE        = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
	// keyValueRE intentionally accepts quoted JSON keys and prefixes such as
	// DB_PASSWORD or aws_secret_access_key.  Masking is deliberately broader
	// than diagnosis matching: a false positive is safer than credential
	// disclosure in a persisted report.
	keyValueRE      = regexp.MustCompile(`(?i)(["']?[a-z0-9_.-]*(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|client[-_]?secret)[a-z0-9_.-]*["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)`)
	sensitiveKeyRE  = regexp.MustCompile(`(?i)^[a-z0-9_.-]*(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|client[-_]?secret|authorization|cookie|private[-_]?key)[a-z0-9_.-]*$`)
	uriCredentialRE = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+(@)`)
	jwtRE           = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	privateKeyRE    = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	vendorTokenRE   = regexp.MustCompile(`\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`)
)

// MaskSecrets replaces common credential forms while retaining enough key
// context to understand the diagnostic message.
func MaskSecrets(value string) string {
	if value == "" {
		return value
	}
	value = SanitizeText(value)
	value = privateKeyRE.ReplaceAllString(value, "<masked-private-key>")
	value = authorizationRE.ReplaceAllString(value, `${1}<masked>`)
	value = cookieHeaderRE.ReplaceAllString(value, `${1}<masked>`)
	value = bearerRE.ReplaceAllString(value, "Bearer <masked>")
	value = keyValueRE.ReplaceAllString(value, `${1}<masked>`)
	value = uriCredentialRE.ReplaceAllString(value, `${1}<masked>${2}`)
	value = jwtRE.ReplaceAllString(value, "<masked-jwt>")
	value = vendorTokenRE.ReplaceAllString(value, "<masked-token>")
	return value
}

// SanitizeText removes terminal control and bidirectional override characters
// from untrusted Kubernetes/API/log text. Newlines and tabs remain available
// for ordinary diagnostic formatting; secret masking is a separate policy.
func SanitizeText(value string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f:
			return -1
		case r == 0x200e || r == 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069:
			return -1
		default:
			return r
		}
	}, value)
}

// IsSensitiveKey protects structured values whose key and value are no longer
// present in one string for keyValueRE to inspect.
func IsSensitiveKey(value string) bool { return sensitiveKeyRE.MatchString(value) }
