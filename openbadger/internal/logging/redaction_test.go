package logging

import (
	"log/slog"
	"strings"
	"testing"
)

func TestRedactString(t *testing.T) {
	t.Parallel()

	value := `password=secret-password authorization="Bearer node-token" {"community":"public"}`
	got := RedactString(value)

	if got == value {
		t.Fatalf("RedactString() = %q, want redacted output", got)
	}

	for _, secret := range []string{"secret-password", "node-token", "public"} {
		if strings.Contains(got, secret) {
			t.Fatalf("RedactString() = %q, secret %q should be redacted", got, secret)
		}
	}

	if !strings.Contains(got, redactedValue) {
		t.Fatalf("RedactString() = %q, want %q marker", got, redactedValue)
	}
}

func TestRedactAttrRedactsSecretKey(t *testing.T) {
	t.Parallel()

	attr := redactAttr(nil, slog.String("password", "secret-password"))
	if got := attr.Value.String(); got != redactedValue {
		t.Fatalf("redactAttr() = %q, want %q", got, redactedValue)
	}
}

func TestRedactAttrRedactsNestedGroup(t *testing.T) {
	t.Parallel()

	attr := redactAttr(nil, slog.Group("credential", slog.String("community", "public"), slog.String("username", "observer")))
	group := attr.Value.Group()
	if len(group) != 2 {
		t.Fatalf("len(group) = %d, want %d", len(group), 2)
	}
	if group[0].Value.String() != redactedValue {
		t.Fatalf("group[0] = %q, want %q", group[0].Value.String(), redactedValue)
	}
	if group[1].Value.String() != "observer" {
		t.Fatalf("group[1] = %q, want %q", group[1].Value.String(), "observer")
	}
}
