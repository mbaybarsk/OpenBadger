package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	ErrMissingBearerToken   = errors.New("missing bearer token")
	ErrMalformedBearerToken = errors.New("malformed bearer token")
)

func GenerateToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate token bytes: %w", err)
	}

	return "obn_" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func HashToken(token string) string {
	token = strings.TrimSpace(token)
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func MatchToken(storedHash string, token string) bool {
	storedHash = strings.TrimSpace(storedHash)
	token = strings.TrimSpace(token)
	if storedHash == "" || token == "" {
		return false
	}

	candidate := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(candidate)) == 1
}

func BearerToken(r *http.Request) (string, error) {
	if r == nil {
		return "", ErrMissingBearerToken
	}

	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return "", ErrMissingBearerToken
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "Bearer") {
		return "", ErrMalformedBearerToken
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", ErrMalformedBearerToken
	}

	return token, nil
}
