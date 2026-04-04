package server

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/nodes"
	"github.com/mbaybarsk/openbadger/internal/schedules"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
	web "github.com/mbaybarsk/openbadger/internal/web"
)

const (
	pageLogin       = "login"
	pageDashboard   = "dashboard"
	pageNodes       = "nodes"
	pageJobs        = "jobs"
	pageSchedules   = "schedules"
	pageAssets      = "assets"
	pageAssetDetail = "asset_detail"
	webListLimit    = 100
	webRecentLimit  = 5
)

var (
	templateSetOnce sync.Once
	templateSetData *templateSet
	templateSetErr  error
)

type webUI struct {
	auth      *adminAuthService
	templates *templateSet
	nodes     *nodeService
	jobs      *jobService
	schedules *scheduleService
	assets    *assetService
}

type templateSet struct {
	pages map[string]*template.Template
}

type basePageData struct {
	Title         string
	CurrentPath   string
	AdminUsername string
}

type loginPageData struct {
	basePageData
	Error string
	Next  string
}

type dashboardPageData struct {
	basePageData
	NodeCount         int
	JobCount          int
	ScheduleCount     int
	AssetCount        int
	RecentNodes       []nodes.DebugRecord
	RecentJobs        []jobtypes.Record
	UpcomingSchedules []schedules.Record
	RecentAssets      []postgres.AssetListItem
}

type nodesPageData struct {
	basePageData
	Nodes []nodes.DebugRecord
}

type jobsPageData struct {
	basePageData
	Jobs []jobtypes.Record
}

type schedulesPageData struct {
	basePageData
	Schedules []schedules.Record
}

type assetsPageData struct {
	basePageData
	Assets []postgres.AssetListItem
}

type assetDetailPageData struct {
	basePageData
	Detail postgres.AssetDetail
}

func newWebUI(options HandlerOptions) *webUI {
	templates := mustLoadTemplateSet()
	return &webUI{
		auth:      options.AdminAuthService,
		templates: templates,
		nodes:     options.NodeService,
		jobs:      options.JobService,
		schedules: options.ScheduleService,
		assets:    options.AssetService,
	}
}

func mustLoadTemplateSet() *templateSet {
	templateSetOnce.Do(func() {
		templateSetData, templateSetErr = newTemplateSet()
	})
	if templateSetErr != nil {
		panic(templateSetErr)
	}

	return templateSetData
}

func newTemplateSet() (*templateSet, error) {
	funcs := template.FuncMap{
		"formatTime": func(value time.Time) string {
			if value.IsZero() {
				return "—"
			}
			return value.UTC().Format("2006-01-02 15:04:05 MST")
		},
		"formatTimePtr": func(value *time.Time) string {
			if value == nil || value.IsZero() {
				return "—"
			}
			return value.UTC().Format("2006-01-02 15:04:05 MST")
		},
		"join": func(values []string, separator string) string {
			if len(values) == 0 {
				return "—"
			}
			return strings.Join(values, separator)
		},
	}

	pages := map[string]*template.Template{}
	for _, page := range []string{pageLogin, pageDashboard, pageNodes, pageJobs, pageSchedules, pageAssets, pageAssetDetail} {
		tmpl, err := template.New("layout").Funcs(funcs).ParseFS(web.TemplatesFS, "templates/layout.tmpl", "templates/"+page+".tmpl")
		if err != nil {
			return nil, fmt.Errorf("parse template %q: %w", page, err)
		}
		pages[page] = tmpl
	}

	return &templateSet{pages: pages}, nil
}

func (s *templateSet) Render(w io.Writer, page string, data any) error {
	if s == nil {
		return fmt.Errorf("template set is required")
	}

	tmpl, ok := s.pages[page]
	if !ok {
		return fmt.Errorf("template %q is not configured", page)
	}

	return tmpl.ExecuteTemplate(w, "layout", data)
}

func (w *webUI) requireAuth(next http.Handler) http.Handler {
	if w == nil || w.auth == nil || !w.auth.enabled() {
		return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, "admin auth unavailable", http.StatusServiceUnavailable)
		})
	}

	return w.auth.Require(next)
}

func (w *webUI) loginHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w == nil || w.auth == nil || !w.auth.enabled() {
			http.Error(rw, "admin auth unavailable", http.StatusServiceUnavailable)
			return
		}

		switch r.Method {
		case http.MethodGet:
			if username, err := w.auth.authenticatedUsername(r); err == nil {
				_ = username
				http.Redirect(rw, r, "/", http.StatusSeeOther)
				return
			}

			w.render(rw, pageLogin, loginPageData{
				basePageData: basePageData{Title: "Login", CurrentPath: "/login"},
				Next:         sanitizeNextPath(r.URL.Query().Get("next"), "/"),
			})
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(rw, "invalid form", http.StatusBadRequest)
				return
			}

			next := sanitizeNextPath(r.FormValue("next"), "/")
			if err := w.auth.Authenticate(r.FormValue("username"), r.FormValue("password")); err != nil {
				rw.WriteHeader(http.StatusUnauthorized)
				w.render(rw, pageLogin, loginPageData{
					basePageData: basePageData{Title: "Login", CurrentPath: "/login"},
					Error:        adminAuthError(err),
					Next:         next,
				})
				return
			}

			if err := w.auth.BeginSession(rw, r, strings.TrimSpace(r.FormValue("username"))); err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}

			http.Redirect(rw, r, next, http.StatusSeeOther)
		default:
			rw.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
			rw.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

func (w *webUI) logoutHandler(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.Header().Set("Allow", http.MethodPost)
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.auth.clearSession(rw, r)
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

func (w *webUI) dashboardHandler(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		rw.Header().Set("Allow", http.MethodGet)
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path != "/" {
		http.NotFound(rw, r)
		return
	}

	nodeRecords, err := w.nodes.ListNodes(r.Context())
	if err != nil {
		writePageError(rw, err)
		return
	}
	jobRecords, err := w.jobs.List(r.Context(), webListLimit)
	if err != nil {
		writePageError(rw, err)
		return
	}
	scheduleRecords, err := w.schedules.List(r.Context(), webListLimit)
	if err != nil {
		writePageError(rw, err)
		return
	}
	assetRecords, err := w.assets.List(r.Context(), "", webListLimit)
	if err != nil {
		writePageError(rw, err)
		return
	}

	sortNodesForDisplay(nodeRecords)
	data := dashboardPageData{
		basePageData: basePageData{
			Title:         "Overview",
			CurrentPath:   "/",
			AdminUsername: adminUsernameFromContext(r.Context()),
		},
		NodeCount:         len(nodeRecords),
		JobCount:          len(jobRecords),
		ScheduleCount:     len(scheduleRecords),
		AssetCount:        len(assetRecords),
		RecentNodes:       limitNodes(nodeRecords, webRecentLimit),
		RecentJobs:        limitJobs(jobRecords, webRecentLimit),
		UpcomingSchedules: limitSchedules(scheduleRecords, webRecentLimit),
		RecentAssets:      limitAssets(assetRecords, webRecentLimit),
	}

	w.render(rw, pageDashboard, data)
}

func (w *webUI) nodesPageHandler(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		rw.Header().Set("Allow", http.MethodGet)
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	records, err := w.nodes.ListNodes(r.Context())
	if err != nil {
		writePageError(rw, err)
		return
	}

	sortNodesForDisplay(records)
	w.render(rw, pageNodes, nodesPageData{
		basePageData: basePageData{Title: "Nodes", CurrentPath: "/nodes", AdminUsername: adminUsernameFromContext(r.Context())},
		Nodes:        records,
	})
}

func (w *webUI) jobsPageHandler(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		rw.Header().Set("Allow", http.MethodGet)
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	records, err := w.jobs.List(r.Context(), webListLimit)
	if err != nil {
		writePageError(rw, err)
		return
	}

	w.render(rw, pageJobs, jobsPageData{
		basePageData: basePageData{Title: "Jobs", CurrentPath: "/jobs", AdminUsername: adminUsernameFromContext(r.Context())},
		Jobs:         records,
	})
}

func (w *webUI) schedulesPageHandler(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		rw.Header().Set("Allow", http.MethodGet)
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	records, err := w.schedules.List(r.Context(), webListLimit)
	if err != nil {
		writePageError(rw, err)
		return
	}

	w.render(rw, pageSchedules, schedulesPageData{
		basePageData: basePageData{Title: "Schedules", CurrentPath: "/schedules", AdminUsername: adminUsernameFromContext(r.Context())},
		Schedules:    records,
	})
}

func (w *webUI) assetsPageHandler(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		rw.Header().Set("Allow", http.MethodGet)
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	records, err := w.assets.List(r.Context(), "", webListLimit)
	if err != nil {
		writePageError(rw, err)
		return
	}

	w.render(rw, pageAssets, assetsPageData{
		basePageData: basePageData{Title: "Assets", CurrentPath: "/assets", AdminUsername: adminUsernameFromContext(r.Context())},
		Assets:       records,
	})
}

func (w *webUI) assetDetailPageHandler(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		rw.Header().Set("Allow", http.MethodGet)
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	assetID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/assets/"))
	if assetID == "" || strings.Contains(assetID, "/") {
		http.NotFound(rw, r)
		return
	}

	detail, err := w.assets.Detail(r.Context(), assetID)
	if err != nil {
		writePageError(rw, err)
		return
	}

	w.render(rw, pageAssetDetail, assetDetailPageData{
		basePageData: basePageData{Title: "Asset Detail", CurrentPath: "/assets", AdminUsername: adminUsernameFromContext(r.Context())},
		Detail:       detail,
	})
}

func (w *webUI) render(rw http.ResponseWriter, page string, data any) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := w.templates.Render(rw, page, data); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func writePageError(rw http.ResponseWriter, err error) {
	var unavailable serviceUnavailableError
	switch {
	case errors.As(err, &unavailable):
		http.Error(rw, err.Error(), http.StatusServiceUnavailable)
	case errors.Is(err, postgres.ErrAssetNotFound):
		http.Error(rw, err.Error(), http.StatusNotFound)
	default:
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}
}

func sortNodesForDisplay(records []nodes.DebugRecord) {
	sort.Slice(records, func(i int, j int) bool {
		if records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].NodeID < records[j].NodeID
		}
		return records[i].CreatedAt.After(records[j].CreatedAt)
	})
}

func limitNodes(records []nodes.DebugRecord, limit int) []nodes.DebugRecord {
	if len(records) <= limit {
		return append([]nodes.DebugRecord(nil), records...)
	}
	return append([]nodes.DebugRecord(nil), records[:limit]...)
}

func limitJobs(records []jobtypes.Record, limit int) []jobtypes.Record {
	if len(records) <= limit {
		return append([]jobtypes.Record(nil), records...)
	}
	return append([]jobtypes.Record(nil), records[:limit]...)
}

func limitSchedules(records []schedules.Record, limit int) []schedules.Record {
	if len(records) <= limit {
		return append([]schedules.Record(nil), records...)
	}
	return append([]schedules.Record(nil), records[:limit]...)
}

func limitAssets(records []postgres.AssetListItem, limit int) []postgres.AssetListItem {
	if len(records) <= limit {
		return append([]postgres.AssetListItem(nil), records...)
	}
	return append([]postgres.AssetListItem(nil), records[:limit]...)
}
