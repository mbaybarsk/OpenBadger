package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	jobtypes "github.com/mbaybarsk/openbadger/internal/jobs"
	"github.com/mbaybarsk/openbadger/internal/schedules"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
)

type scheduleStore interface {
	CreateSchedule(ctx context.Context, params schedules.CreateRequest) (schedules.Record, error)
	ListSchedules(ctx context.Context, limit int) ([]schedules.Record, error)
	ListDueSchedules(ctx context.Context, now time.Time, limit int) ([]postgres.DueSchedule, error)
	MarkScheduleRun(ctx context.Context, params postgres.UpdateScheduleRunParams) (schedules.Record, error)
	CreateJob(ctx context.Context, params postgres.CreateJobParams) (jobtypes.Record, error)
	DeleteObservationsBefore(ctx context.Context, cutoff time.Time) (int64, error)
}

type scheduleService struct {
	store scheduleStore
}

func newScheduleService(store scheduleStore) *scheduleService {
	return &scheduleService{store: store}
}

func (s *scheduleService) Create(ctx context.Context, request schedules.CreateRequest) (schedules.Record, error) {
	if s == nil || s.store == nil {
		return schedules.Record{}, errServiceUnavailable("schedule")
	}

	return s.store.CreateSchedule(ctx, request)
}

func (s *scheduleService) List(ctx context.Context, limit int) ([]schedules.Record, error) {
	if s == nil || s.store == nil {
		return nil, errServiceUnavailable("schedule")
	}

	return s.store.ListSchedules(ctx, limit)
}

func debugSchedulesHandler(service *scheduleService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if service == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "schedule service unavailable")
			return
		}

		var request schedules.CreateRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		record, err := service.Create(r.Context(), request)
		if err != nil {
			writeAdminError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, schedules.DebugCreateResponse{Schedule: record})
	}
}

func writeAdminError(w http.ResponseWriter, err error) {
	var unavailable serviceUnavailableError
	switch {
	case errors.As(err, &unavailable):
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
	case isValidationError(err):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, "internal server error")
	}
}

type serviceUnavailableError string

func (e serviceUnavailableError) Error() string {
	name := string(e)
	if name == "" {
		return "service unavailable"
	}

	return fmt.Sprintf("%s service is unavailable", name)
}

func errServiceUnavailable(name string) error {
	return serviceUnavailableError(name)
}
