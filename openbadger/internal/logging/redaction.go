package logging

import (
	"log/slog"
	"regexp"
	"strings"
)

const redactedValue = "[REDACTED]"

var redactionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)("?(?:password|passphrase|community|token|secret|private_key|auth_password|privacy_password|authorization)"?\s*[:=]\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)(\b(?:password|passphrase|community|token|secret|private_key|auth_password|privacy_password|authorization)\b\s*=\s*)([^\s,]+)`),
	regexp.MustCompile(`(?i)(Bearer\s+)([^\s]+)`),
}

func RedactString(value string) string {
	redacted := value
	for _, pattern := range redactionPatterns {
		redacted = pattern.ReplaceAllString(redacted, `${1}`+redactedValue+`${3}`)
	}
	return redacted
}

func redactAttr(_ []string, attr slog.Attr) slog.Attr {
	attr.Value = attr.Value.Resolve()

	if shouldRedactKey(attr.Key) {
		return slog.String(attr.Key, redactedValue)
	}

	switch attr.Value.Kind() {
	case slog.KindString:
		return slog.String(attr.Key, RedactString(attr.Value.String()))
	case slog.KindGroup:
		children := attr.Value.Group()
		redacted := make([]slog.Attr, 0, len(children))
		for _, child := range children {
			redacted = append(redacted, redactAttr(nil, child))
		}
		return slog.Attr{Key: attr.Key, Value: slog.GroupValue(redacted...)}
	default:
		return attr
	}
}

func shouldRedactKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return false
	}

	for _, secretKey := range []string{"password", "passphrase", "community", "token", "secret", "private_key", "auth_password", "privacy_password", "authorization", "credential_encryption_key"} {
		if key == secretKey || strings.HasSuffix(key, "."+secretKey) || strings.HasSuffix(key, "_"+secretKey) {
			return true
		}
	}

	return false
}
