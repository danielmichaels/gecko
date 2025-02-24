package jobs

import (
	"context"
	"log/slog"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

const (
	queueEnumeration = "queue_enumeration"
	queueResolver    = "queue_resolver"
	queueScanner     = "queue_scanner"
	queueAssessor    = "queue_assessor"
)

type Config struct {
	PgxPool     *pgxpool.Pool
	Logger      *slog.Logger
	Store       *store.Queries
	WorkerCount int
	AddWorkers  bool
}

// New creates a new River client.
func New(ctx context.Context, cfg Config) (*river.Client[pgx.Tx], error) {
	migrator, err := rivermigrate.New(riverpgxv5.New(cfg.PgxPool), nil)
	if err != nil {
		return nil, err
	}
	res, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	if err != nil {
		return nil, err
	}
	for _, version := range res.Versions {
		cfg.Logger.Info(
			"river migrations ran",
			"direction",
			res.Direction,
			"version",
			version.Version,
		)
	}

	riverConfig := &river.Config{}
	rw := river.NewWorkers()
	if cfg.AddWorkers {
		// special case: scan orchestrator
		river.AddWorker(rw, &ScanNewDomainWorker{Logger: *cfg.Logger, Store: cfg.Store, PgxPool: cfg.PgxPool})
		// scan workers
		river.AddWorker(rw, &EnumerateSubdomainWorker{Logger: *cfg.Logger, DB: cfg.PgxPool})
		river.AddWorker(rw, &ResolveDomainWorker{Logger: *cfg.Logger, Store: cfg.Store})
		river.AddWorker(rw, &ScanCertificateWorker{Logger: *cfg.Logger, Store: cfg.Store})
		river.AddWorker(rw, &ScanCNAMEWorker{Logger: *cfg.Logger, Store: cfg.Store})
		river.AddWorker(rw, &ScanDNSSECWorker{Logger: *cfg.Logger, Store: cfg.Store})
		river.AddWorker(rw, &ScanZoneTransferWorker{Logger: *cfg.Logger, Store: cfg.Store})
		// assess workers
		river.AddWorker(rw, &AssessCNAMEDanglingWorker{Logger: *cfg.Logger, Store: cfg.Store})
		riverConfig.Workers = rw
		riverConfig.MaxAttempts = 5
		riverConfig.Queues = map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: cfg.WorkerCount},
			// reserved for DNS resolution only
			queueResolver: {MaxWorkers: cfg.WorkerCount},
			// reserved for subdomain enumeration
			queueEnumeration: {MaxWorkers: cfg.WorkerCount},
			// reserved for scanners
			queueScanner: {MaxWorkers: cfg.WorkerCount},
			// reserved for assessors
			queueAssessor: {MaxWorkers: cfg.WorkerCount},
		}
	}

	rc, err := river.NewClient(riverpgxv5.New(cfg.PgxPool), riverConfig)
	if err != nil {
		return nil, err
	}
	return rc, nil
}
