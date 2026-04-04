package server

import (
	"encoding/json"
	"expvar"
	"net/http"
)

type HandlerOptions struct {
	NodeService              *nodeService
	JobService               *jobService
	ObservationService       *observationService
	AssetService             *assetService
	TargetRangeService       *targetRangeService
	CredentialProfileService *credentialProfileService
	ScanProfileService       *scanProfileService
	ScheduleService          *scheduleService
	AdminAuthService         *adminAuthService
}

type errorResponse struct {
	Error string `json:"error"`
}

func NewHandler() http.Handler {
	return newHandler(HandlerOptions{})
}

func newHandler(options HandlerOptions) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/readyz", readyHandler)
	mux.HandleFunc("/api/v1/nodes/enroll", nodeEnrollHandler(options.NodeService))
	mux.HandleFunc("/api/v1/nodes/heartbeat", nodeHeartbeatHandler(options.NodeService))
	mux.HandleFunc("/api/v1/jobs/lease", jobLeaseHandler(options.JobService))
	mux.HandleFunc("/api/v1/jobs/", jobStatusHandler(options.JobService))
	mux.HandleFunc("/api/v1/observations/batch", observationBatchHandler(options.ObservationService))
	mux.HandleFunc("/api/v1/assets.csv", assetsCSVHandler(options.AssetService))
	mux.HandleFunc("/api/v1/assets/", assetDetailHandler(options.AssetService))
	mux.HandleFunc("/api/v1/assets", assetsHandler(options.AssetService))
	mux.HandleFunc("/debug/nodes", debugNodesHandler(options.NodeService))
	mux.HandleFunc("/debug/jobs", debugJobsHandler(options.JobService))
	mux.HandleFunc("/debug/observations", debugObservationsHandler(options.ObservationService))
	mux.HandleFunc("/debug/target-ranges", debugTargetRangesHandler(options.TargetRangeService))
	mux.HandleFunc("/debug/credential-profiles", debugCredentialProfilesHandler(options.CredentialProfileService))
	mux.HandleFunc("/debug/scan-profiles", debugScanProfilesHandler(options.ScanProfileService))
	mux.HandleFunc("/debug/schedules", debugSchedulesHandler(options.ScheduleService))
	mux.Handle("/debug/vars", expvar.Handler())

	webUI := newWebUI(options)
	mux.Handle("/login", webUI.loginHandler())
	mux.Handle("/logout", webUI.requireAuth(http.HandlerFunc(webUI.logoutHandler)))
	mux.Handle("/nodes", webUI.requireAuth(http.HandlerFunc(webUI.nodesPageHandler)))
	mux.Handle("/jobs", webUI.requireAuth(http.HandlerFunc(webUI.jobsPageHandler)))
	mux.Handle("/schedules", webUI.requireAuth(http.HandlerFunc(webUI.schedulesPageHandler)))
	mux.Handle("/assets/", webUI.requireAuth(http.HandlerFunc(webUI.assetDetailPageHandler)))
	mux.Handle("/assets", webUI.requireAuth(http.HandlerFunc(webUI.assetsPageHandler)))
	mux.Handle("/", webUI.requireAuth(http.HandlerFunc(webUI.dashboardHandler)))

	return mux
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSONStatus(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	writeJSONStatus(w, r, http.StatusOK, map[string]string{"status": "ready"})
}

func writeJSONStatus(w http.ResponseWriter, r *http.Request, statusCode int, payload map[string]string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, statusCode, payload)
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, errorResponse{Error: message})
}
