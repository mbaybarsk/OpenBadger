package ops

import "expvar"

var (
	CredentialProfilesCreatedTotal = expvar.NewInt("openbadger_credential_profiles_created_total")
	NodeHeartbeatsTotal            = expvar.NewInt("openbadger_node_heartbeats_total")
	ObservationBatchesTotal        = expvar.NewInt("openbadger_observation_batches_total")
	ObservationsAcceptedTotal      = expvar.NewInt("openbadger_observations_accepted_total")
	ScheduledJobsCreatedTotal      = expvar.NewInt("openbadger_scheduled_jobs_created_total")
	ObservationRetentionRunsTotal  = expvar.NewInt("openbadger_observation_retention_runs_total")
	ObservationsDeletedTotal       = expvar.NewInt("openbadger_observations_deleted_total")
)
