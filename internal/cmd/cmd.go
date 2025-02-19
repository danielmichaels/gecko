package cmd

import (
	"context"
	"github.com/danielmichaels/doublestag/internal/config"
	"github.com/danielmichaels/doublestag/internal/jobs"
	"github.com/danielmichaels/doublestag/internal/logging"
	"github.com/danielmichaels/doublestag/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"io"
	"log/slog"
)

type Globals struct{}

type Setup struct {
	Config *config.Conf
	Logger *slog.Logger
	DB     *pgxpool.Pool
	Store  *store.Queries
	Ctx    context.Context
	Cancel context.CancelFunc
	RC     *river.Client[pgx.Tx]
}
type SetupOption func(*Setup)

// WithRiver sets up a River client.
//
// workerCount is the number of workers to start.
//
// addWorkers is whether to add workers to the River client. Used in server to disable workers.
func WithRiver(workerCount int, addWorkers bool) SetupOption {
	return func(s *Setup) {
		riverCfg := jobs.Config{
			DB:          s.DB,
			Logger:      s.Logger,
			Store:       s.Store,
			WorkerCount: workerCount,
			AddWorkers:  addWorkers,
		}

		rc, err := jobs.New(s.Ctx, riverCfg)
		if err != nil {
			// fixme: handle error
			panic("failed to create River client: " + err.Error())
		}
		s.RC = rc
	}
}

// WithSilentLogging is the default mode for CLI commands. It discards
// logs. CLI then relies upon printing. Using Verbose turns this off and
// logs will be output on CLI invocation.
func WithSilentLogging() SetupOption {
	return func(s *Setup) {
		handler := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{})
		s.Logger = slog.New(handler)
	}
}

func NewSetup(service string, opts ...SetupOption) (*Setup, error) {
	cfg := config.AppConfig()
	logger, lctx := logging.SetupLogger(service, cfg)
	ctx, cancel := context.WithCancel(lctx)

	db, err := store.NewDatabasePool(ctx, cfg)
	if err != nil {
		logger.Error("database error", "error", err)
		cancel()
		return nil, err
	}

	if err := db.Ping(ctx); err != nil {
		logger.Error("database ping error", "error", err)
		db.Close()
		cancel()
		return nil, err
	}
	s := &Setup{
		Config: cfg,
		Logger: logger,
		DB:     db,
		Store:  store.New(db),
		Ctx:    ctx,
		Cancel: cancel,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func (s *Setup) Close() {
	s.Logger.Info("shutting down DB and River")
	if s.RC != nil {
		if err := s.RC.Stop(s.Ctx); err != nil { // Use Stop instead of Close
			s.Logger.Error("failed to stop River client", "error", err)
		}
	}
	s.Cancel()
	s.DB.Close()
	s.Logger.Info("shutdown complete")
}
