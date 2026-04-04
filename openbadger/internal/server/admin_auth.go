package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const adminSessionCookieName = "openbadger_admin_session"

var (
	errInvalidAdminCredentials = errors.New("invalid admin credentials")
	errInvalidAdminSession     = errors.New("invalid admin session")
)

type adminContextKey string

const adminUsernameContextKey adminContextKey = "admin_username"

type adminAuthService struct {
	username string
	password string
	secret   []byte
	ttl      time.Duration
	now      func() time.Time
}

func newAdminAuthService(username string, password string, secret string, ttl time.Duration, now func() time.Time) *adminAuthService {
	if now == nil {
		now = time.Now
	}

	if ttl <= 0 {
		ttl = 12 * time.Hour
	}

	return &adminAuthService{
		username: strings.TrimSpace(username),
		password: password,
		secret:   []byte(strings.TrimSpace(secret)),
		ttl:      ttl,
		now:      now,
	}
}

func (s *adminAuthService) enabled() bool {
	return s != nil && s.username != "" && s.password != "" && len(s.secret) > 0
}

func (s *adminAuthService) Authenticate(username string, password string) error {
	if !s.enabled() {
		return errServiceUnavailable("admin auth")
	}

	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(username)), []byte(s.username)) != 1 || subtle.ConstantTimeCompare([]byte(password), []byte(s.password)) != 1 {
		return errInvalidAdminCredentials
	}

	return nil
}

func (s *adminAuthService) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.enabled() {
			http.Error(w, "admin auth unavailable", http.StatusServiceUnavailable)
			return
		}

		username, err := s.authenticatedUsername(r)
		if err != nil {
			s.clearSession(w, r)
			redirectToLogin(w, r)
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminUsernameContextKey, username)))
	})
}

func (s *adminAuthService) authenticatedUsername(r *http.Request) (string, error) {
	if !s.enabled() {
		return "", errServiceUnavailable("admin auth")
	}

	cookie, err := r.Cookie(adminSessionCookieName)
	if err != nil {
		return "", errInvalidAdminSession
	}

	return s.verifySessionValue(cookie.Value)
}

func (s *adminAuthService) BeginSession(w http.ResponseWriter, r *http.Request, username string) error {
	value, expiresAt, err := s.issueSessionValue(username)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   requestIsSecure(r),
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})

	return nil
}

func (s *adminAuthService) clearSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   requestIsSecure(r),
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
	})
}

func (s *adminAuthService) issueSessionValue(username string) (string, time.Time, error) {
	if !s.enabled() {
		return "", time.Time{}, errServiceUnavailable("admin auth")
	}

	expiresAt := s.now().UTC().Add(s.ttl)
	encodedUsername := base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(username)))
	payload := encodedUsername + "." + strconv.FormatInt(expiresAt.Unix(), 10)
	signature := base64.RawURLEncoding.EncodeToString(s.sign(payload))
	return payload + "." + signature, expiresAt, nil
}

func (s *adminAuthService) verifySessionValue(value string) (string, error) {
	if !s.enabled() {
		return "", errServiceUnavailable("admin auth")
	}

	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 3 {
		return "", errInvalidAdminSession
	}

	payload := parts[0] + "." + parts[1]
	expected := s.sign(payload)
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errInvalidAdminSession
	}

	if !hmac.Equal(provided, expected) {
		return "", errInvalidAdminSession
	}

	expiresUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errInvalidAdminSession
	}

	expiresAt := time.Unix(expiresUnix, 0).UTC()
	if !expiresAt.After(s.now().UTC()) {
		return "", errInvalidAdminSession
	}

	usernameBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errInvalidAdminSession
	}

	username := strings.TrimSpace(string(usernameBytes))
	if username == "" {
		return "", errInvalidAdminSession
	}

	return username, nil
}

func (s *adminAuthService) sign(payload string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}

func adminUsernameFromContext(ctx context.Context) string {
	username, _ := ctx.Value(adminUsernameContextKey).(string)
	return username
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	location := "/login"
	if next := sanitizeNextPath(r.URL.RequestURI(), ""); next != "" && next != "/login" {
		location += "?next=" + url.QueryEscape(next)
	}

	http.Redirect(w, r, location, http.StatusSeeOther)
}

func sanitizeNextPath(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() {
		return fallback
	}

	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return fallback
	}

	if strings.HasPrefix(value, "/login") || strings.HasPrefix(value, "/logout") {
		return fallback
	}

	return value
}

func requestIsSecure(r *http.Request) bool {
	if r != nil && r.TLS != nil {
		return true
	}

	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func adminAuthError(err error) string {
	if errors.Is(err, errInvalidAdminCredentials) {
		return "Invalid username or password"
	}

	return fmt.Sprintf("%v", err)
}
