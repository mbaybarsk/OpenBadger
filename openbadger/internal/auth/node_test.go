package auth

import (
	"net/http"
	"testing"
)

func TestBearerTokenAcceptsBearerHeader(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodPost, "http://example.test", nil)
	if err != nil {
		t.Fatalf("http.NewRequest returned error: %v", err)
	}
	req.Header.Set("Authorization", "Bearer node-token")

	token, err := BearerToken(req)
	if err != nil {
		t.Fatalf("BearerToken returned error: %v", err)
	}

	if token != "node-token" {
		t.Fatalf("token = %q, want %q", token, "node-token")
	}
}

func TestBearerTokenRejectsMissingHeader(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodPost, "http://example.test", nil)
	if err != nil {
		t.Fatalf("http.NewRequest returned error: %v", err)
	}

	_, err = BearerToken(req)
	if err == nil {
		t.Fatal("BearerToken returned nil error, want error")
	}
}

func TestMatchTokenMatchesHashedNodeToken(t *testing.T) {
	t.Parallel()

	hash := HashToken("node-token")
	if !MatchToken(hash, "node-token") {
		t.Fatal("MatchToken returned false, want true")
	}

	if MatchToken(hash, "different-token") {
		t.Fatal("MatchToken returned true, want false")
	}
}
