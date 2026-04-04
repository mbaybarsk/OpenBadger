package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/profiles"
	"github.com/mbaybarsk/openbadger/internal/schedules"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
	"github.com/mbaybarsk/openbadger/internal/targets"
)

func TestLoginHandlerRendersPage(t *testing.T) {
	t.Parallel()

	handler := newWebTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if !strings.Contains(rec.Body.String(), "Admin Login") {
		t.Fatalf("body = %q, want login page", rec.Body.String())
	}
}

func TestLoginHandlerSetsSessionCookie(t *testing.T) {
	t.Parallel()

	handler := newWebTestHandler(t)
	form := url.Values{"username": {"admin"}, "password": {"admin-password"}, "next": {"/jobs"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}

	if location := rec.Header().Get("Location"); location != "/jobs" {
		t.Fatalf("location = %q, want %q", location, "/jobs")
	}

	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("cookies = 0, want session cookie")
	}

	if rec.Result().Cookies()[0].Name != adminSessionCookieName {
		t.Fatalf("cookie name = %q, want %q", rec.Result().Cookies()[0].Name, adminSessionCookieName)
	}
}

func TestLoginHandlerRejectsInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := newWebTestHandler(t)
	form := url.Values{"username": {"admin"}, "password": {"wrong-password"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	if !strings.Contains(rec.Body.String(), "Invalid username or password") {
		t.Fatalf("body = %q, want invalid credential message", rec.Body.String())
	}
}

func TestProtectedPagesRedirectToLoginWithoutSession(t *testing.T) {
	t.Parallel()

	handler := newWebTestHandler(t)
	paths := []string{"/", "/nodes", "/jobs", "/schedules", "/assets"}
	for _, path := range paths {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
			}

			want := "/login?next=" + url.QueryEscape(path)
			if location := rec.Header().Get("Location"); location != want {
				t.Fatalf("location = %q, want %q", location, want)
			}
		})
	}
}

func TestMajorPagesRenderWithAuthenticatedSession(t *testing.T) {
	t.Parallel()

	store := newWebTestStore(t)
	auth := newTestAdminAuth()
	handler := newHandler(HandlerOptions{
		NodeService:      newNodeService(store, "bootstrap-token", nil, nil),
		JobService:       newJobService(store, nil),
		ScheduleService:  newScheduleService(store),
		AssetService:     newAssetService(store),
		AdminAuthService: auth,
	})

	cookie := newAuthenticatedCookie(t, auth)
	assetID := firstAssetID(t, store)
	cases := []struct {
		path string
		want string
	}{
		{path: "/", want: "Overview"},
		{path: "/nodes", want: "collector-1"},
		{path: "/jobs", want: "job-1"},
		{path: "/schedules", want: "every-five"},
		{path: "/assets", want: assetID},
		{path: "/assets/" + assetID, want: "Asset Detail"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}

			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("body = %q, want to contain %q", rec.Body.String(), tc.want)
			}
		})
	}
}

func TestTemplateRenderingSmoke(t *testing.T) {
	t.Parallel()

	templates, err := newTemplateSet()
	if err != nil {
		t.Fatalf("newTemplateSet returned error: %v", err)
	}

	assetDetail := postgres.AssetDetail{Asset: postgres.Asset{ID: "asset-1", SiteID: "site-1", FirstSeen: time.Date(2026, time.April, 4, 9, 0, 0, 0, time.UTC), LastSeen: time.Date(2026, time.April, 4, 10, 0, 0, 0, time.UTC)}}
	tests := []struct {
		page string
		data any
		want string
	}{
		{page: pageLogin, data: loginPageData{basePageData: basePageData{Title: "Login"}}, want: "Admin Login"},
		{page: pageDashboard, data: dashboardPageData{basePageData: basePageData{Title: "Overview", AdminUsername: "admin"}}, want: "Overview"},
		{page: pageNodes, data: nodesPageData{basePageData: basePageData{Title: "Nodes", AdminUsername: "admin"}}, want: "Nodes"},
		{page: pageJobs, data: jobsPageData{basePageData: basePageData{Title: "Jobs", AdminUsername: "admin"}}, want: "Jobs"},
		{page: pageSchedules, data: schedulesPageData{basePageData: basePageData{Title: "Schedules", AdminUsername: "admin"}}, want: "Schedules"},
		{page: pageAssets, data: assetsPageData{basePageData: basePageData{Title: "Assets", AdminUsername: "admin"}}, want: "Assets"},
		{page: pageAssetDetail, data: assetDetailPageData{basePageData: basePageData{Title: "Asset Detail", AdminUsername: "admin"}, Detail: assetDetail}, want: "Asset Detail"},
	}

	for _, tc := range tests {
		var buffer bytes.Buffer
		if err := templates.Render(&buffer, tc.page, tc.data); err != nil {
			t.Fatalf("Render(%q) returned error: %v", tc.page, err)
		}

		if !strings.Contains(buffer.String(), tc.want) {
			t.Fatalf("Render(%q) = %q, want to contain %q", tc.page, buffer.String(), tc.want)
		}
	}
}

func TestAdminSessionMiddleware(t *testing.T) {
	t.Parallel()

	auth := newTestAdminAuth()
	handler := auth.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(adminUsernameFromContext(r.Context())))
	}))

	t.Run("allows valid session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/nodes", nil)
		req.AddCookie(newAuthenticatedCookie(t, auth))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}

		if body := rec.Body.String(); body != "admin" {
			t.Fatalf("body = %q, want %q", body, "admin")
		}
	})

	t.Run("rejects tampered session", func(t *testing.T) {
		cookie := newAuthenticatedCookie(t, auth)
		cookie.Value += "tampered"
		req := httptest.NewRequest(http.MethodGet, "/nodes", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
		}

		if location := rec.Header().Get("Location"); location != "/login?next=%2Fnodes" {
			t.Fatalf("location = %q, want %q", location, "/login?next=%2Fnodes")
		}
	})
}

func newWebTestHandler(t *testing.T) http.Handler {
	t.Helper()

	store := newWebTestStore(t)
	return newHandler(HandlerOptions{
		NodeService:      newNodeService(store, "bootstrap-token", nil, nil),
		JobService:       newJobService(store, nil),
		ScheduleService:  newScheduleService(store),
		AssetService:     newAssetService(store),
		AdminAuthService: newTestAdminAuth(),
	})
}

func newWebTestStore(t *testing.T) *memoryNodeStore {
	t.Helper()

	store := newMemoryNodeStore()
	createdNode, err := store.CreateNode(context.Background(), nodes.CreateParams{
		SiteID:        "site-1",
		Kind:          nodes.KindCollector,
		Name:          "collector-1",
		Version:       "0.1.0",
		Capabilities:  []string{"ssh", "icmp"},
		HealthStatus:  "healthy",
		AuthTokenHash: "node-token-hash",
	})
	if err != nil {
		t.Fatalf("CreateNode returned error: %v", err)
	}

	if _, err := store.CreateJob(context.Background(), postgres.CreateJobParams{
		SiteID:     "site-1",
		NodeID:     &createdNode.ID,
		Kind:       "scan",
		Capability: "ssh",
		Status:     jobtypes.StatusRunning,
	}); err != nil {
		t.Fatalf("CreateJob returned error: %v", err)
	}

	targetRange, err := store.CreateTargetRange(context.Background(), targets.CreateRequest{SiteID: "site-1", Name: "branch-a", CIDR: "192.0.2.0/24"})
	if err != nil {
		t.Fatalf("CreateTargetRange returned error: %v", err)
	}

	scanProfile, err := store.CreateScanProfile(context.Background(), profiles.CreateScanProfileRequest{SiteID: "site-1", Name: "icmp-default", Capability: "icmp"})
	if err != nil {
		t.Fatalf("CreateScanProfile returned error: %v", err)
	}

	if _, err := store.CreateSchedule(context.Background(), schedules.CreateRequest{SiteID: "site-1", Name: "every-five", CronExpression: "*/5 * * * *", TargetRangeID: targetRange.ID, ScanProfileID: scanProfile.ID}); err != nil {
		t.Fatalf("CreateSchedule returned error: %v", err)
	}

	seedAsset(t, store)
	return store
}

func newTestAdminAuth() *adminAuthService {
	return newAdminAuthService(
		"admin",
		"admin-password",
		"0123456789abcdef0123456789abcdef",
		12*time.Hour,
		func() time.Time { return time.Date(2026, time.April, 4, 9, 0, 0, 0, time.UTC) },
	)
}

func newAuthenticatedCookie(t *testing.T, auth *adminAuthService) *http.Cookie {
	t.Helper()

	value, _, err := auth.issueSessionValue("admin")
	if err != nil {
		t.Fatalf("issueSessionValue returned error: %v", err)
	}

	return &http.Cookie{Name: adminSessionCookieName, Value: value}
}

func firstAssetID(t *testing.T, store *memoryNodeStore) string {
	t.Helper()

	assets, err := store.ListAssets(context.Background(), postgres.ListAssetsParams{})
	if err != nil {
		t.Fatalf("ListAssets returned error: %v", err)
	}

	if len(assets) == 0 {
		t.Fatal("assets = 0, want at least one asset")
	}

	return assets[0].Asset.ID
}

func (s *memoryNodeStore) ListJobs(_ context.Context, limit int) ([]jobtypes.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	jobIDs := append([]string(nil), s.jobOrder...)
	for left, right := 0, len(jobIDs)-1; left < right; left, right = left+1, right-1 {
		jobIDs[left], jobIDs[right] = jobIDs[right], jobIDs[left]
	}

	if limit <= 0 || limit > len(jobIDs) {
		limit = len(jobIDs)
	}

	result := make([]jobtypes.Record, 0, limit)
	for _, jobID := range jobIDs[:limit] {
		result = append(result, s.jobsByID[jobID])
	}

	return result, nil
}

func (s *memoryNodeStore) ListSchedules(_ context.Context, limit int) ([]schedules.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]schedules.Record, 0, len(s.schedulesByID))
	for _, record := range s.schedulesByID {
		result = append(result, record)
	}

	sort.Slice(result, func(i int, j int) bool {
		if result[i].NextRunAt.Equal(result[j].NextRunAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].NextRunAt.Before(result[j].NextRunAt)
	})

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}
