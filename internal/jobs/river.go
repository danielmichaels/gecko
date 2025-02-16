package jobs

import (
	"context"
	"github.com/danielmichaels/doublestag/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"log/slog"
)

type Config struct {
	DB          *pgxpool.Pool
	Logger      *slog.Logger
	Store       *store.Queries
	WorkerCount int
	AddWorkers  bool
}

// New creates a new River client.
func New(ctx context.Context, cfg Config) (*river.Client[pgx.Tx], error) {
	migrator, err := rivermigrate.New(riverpgxv5.New(cfg.DB), nil)
	if err != nil {
		return nil, err
	}
	res, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	if err != nil {
		return nil, err
	}
	for _, version := range res.Versions {
		cfg.Logger.Info("river migrations ran", "direction", res.Direction, "version", version.Version)
	}

	rw := river.NewWorkers()
	if cfg.AddWorkers {
		river.AddWorker(rw, &EnumerateSubdomainWorker{Logger: *cfg.Logger, DB: cfg.DB})
		river.AddWorker(rw, &ResolveDomainWorker{Logger: *cfg.Logger, Store: cfg.Store})
	}

	rc, err := river.NewClient(riverpgxv5.New(cfg.DB), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: cfg.WorkerCount},
		},
		Workers: rw,
	})
	if err != nil {
		return nil, err
	}
	return rc, nil
}
