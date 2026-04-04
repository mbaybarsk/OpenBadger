package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/mbaybarsk/openbadger/internal/config"
	"github.com/mbaybarsk/openbadger/internal/credentials"
	"github.com/mbaybarsk/openbadger/internal/storage/postgres"
)

func Run(ctx context.Context, cfg config.ServerConfig, database config.DatabaseConfig, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	db, err := postgres.Open(ctx, database.URL)
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer db.Close()

	secretBox, err := credentials.NewSecretBox(cfg.CredentialEncryptionKey)
	if err != nil {
		return fmt.Errorf("create credential secret box: %w", err)
	}

	repository := postgres.NewRepositoryWithOptions(db, postgres.RepositoryOptions{SecretBox: secretBox})
	scheduler := newSchedulerService(repository, nil).WithObservationRetention(cfg.ObservationRetention)
	nodeService := newNodeService(repository, cfg.EnrollmentToken, nil, nil).WithHeartbeatPolicy(cfg.ExpectedHeartbeatInterval, cfg.StaleAfterMissedHeartbeats)

	httpServer := &http.Server{
		Addr: cfg.Address,
		Handler: newHandler(HandlerOptions{
			NodeService:              nodeService,
			JobService:               newJobService(repository, nil),
			ObservationService:       newObservationService(repository),
			AssetService:             newAssetService(repository),
			TargetRangeService:       newTargetRangeService(repository),
			CredentialProfileService: newCredentialProfileService(repository),
			ScanProfileService:       newScanProfileService(repository),
			ScheduleService:          newScheduleService(repository),
			AdminAuthService:         newAdminAuthService(cfg.AdminUsername, cfg.AdminPassword, cfg.AdminSessionSecret, cfg.AdminSessionTTL, nil),
		}),
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	httpErrCh := make(chan error, 1)
	schedulerErrCh := make(chan error, 1)

	go func() {
		logger.Info("starting mode", "mode", "server", "address", cfg.Address)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErrCh <- fmt.Errorf("listen and serve: %w", err)
			return
		}

		httpErrCh <- nil
	}()

	go func() {
		schedulerErrCh <- scheduler.Run(runCtx, cfg.SchedulerInterval, logger.With("component", "scheduler"))
	}()

	select {
	case <-ctx.Done():
		logger.Info("stopping mode", "mode", "server", "reason", ctx.Err())
		cancelRun()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout(cfg.ShutdownTimeout))
		defer cancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown server: %w", err)
		}

		httpErr := <-httpErrCh
		schedulerErr := <-schedulerErrCh
		if httpErr != nil {
			return httpErr
		}

		return schedulerErr
	case err := <-httpErrCh:
		cancelRun()
		<-schedulerErrCh
		return err
	case err := <-schedulerErrCh:
		cancelRun()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout(cfg.ShutdownTimeout))
		defer cancel()

		if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
			return fmt.Errorf("shutdown server after scheduler error: %w", shutdownErr)
		}

		<-httpErrCh
		return err
	}

}

func shutdownTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 5 * time.Second
	}

	return timeout
}
