package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
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
	Resolver    dnsclient.Resolver
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

	if cfg.Resolver == nil {
		// DNSClient holds the fleet-wide limiter and shared cache internally; both
		// read their feature flags from config and no-op when disabled or when no
		// store is supplied.
		cfg.Resolver = dnsclient.New(
			dnsclient.WithLimiter(dnsclient.NewPgRateLimiter(cfg.Store)),
			dnsclient.WithCache(cfg.Store),
		)
	}
	seedRateLimitBucket(ctx, cfg.Store, cfg.Logger)

	riverConfig := &river.Config{}
	riverConfig.Hooks = []rivertype.Hook{&CorrelationInsertHook{}}
	rw := river.NewWorkers()
	if cfg.AddWorkers {
		// scan workers
		river.AddWorker(
			rw,
			&EnumerateSubdomainWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&ResolveDomainWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&ScanCertificateWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&ScanCNAMEWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&ScanDNSSECWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&ScanZoneTransferWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		// assess workers
		river.AddWorker(
			rw,
			&AssessCNAMEDanglingWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&AssessZoneTransferWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&AssessEmailSecurityWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		// maintenance
		river.AddWorker(rw, &PurgeDNSCacheWorker{Logger: *cfg.Logger, Store: cfg.Store})
		river.AddWorker(rw, &RefreshTenantStatsWorker{Logger: *cfg.Logger, Store: cfg.Store})
		riverConfig.Workers = rw
		riverConfig.Middleware = []rivertype.Middleware{
			&CorrelationMiddleware{},
			&TimingMiddleware{Logger: cfg.Logger},
		}
		riverConfig.MaxAttempts = 5
		riverConfig.Queues = map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: cfg.WorkerCount},
			// reserved for DNS resolution only
			queueResolver: {MaxWorkers: cfg.WorkerCount},
			// reserved for subdomain enumeration; capped independently to bound
			// pressure on subfinder's upstream providers under HA.
			queueEnumeration: {MaxWorkers: enumerationWorkers(cfg.WorkerCount)},
			// reserved for scanners
			queueScanner: {MaxWorkers: cfg.WorkerCount},
			// reserved for assessors
			queueAssessor: {MaxWorkers: cfg.WorkerCount},
		}
		riverConfig.PeriodicJobs = []*river.PeriodicJob{
			river.NewPeriodicJob(
				river.PeriodicInterval(30*time.Second),
				func() (river.JobArgs, *river.InsertOpts) {
					return RefreshTenantStatsArgs{}, nil
				},
				&river.PeriodicJobOpts{RunOnStart: true},
			),
		}
		if config.AppConfig().AppConf.DNSCacheEnabled {
			riverConfig.PeriodicJobs = append(
				riverConfig.PeriodicJobs,
				river.NewPeriodicJob(
					river.PeriodicInterval(15*time.Minute),
					func() (river.JobArgs, *river.InsertOpts) {
						return PurgeDNSCacheArgs{}, nil
					},
					&river.PeriodicJobOpts{RunOnStart: true},
				),
			)
		}
	}

	rc, err := river.NewClient(riverpgxv5.New(cfg.PgxPool), riverConfig)
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// enumerationWorkers returns the per-process cap for the enumeration queue,
// falling back to the general worker count when ENUMERATION_WORKER_COUNT is unset
// (0) or negative.
func enumerationWorkers(fallback int) int {
	n := config.AppConfig().AppConf.EnumerationWorkerCount
	if n <= 0 {
		return fallback
	}
	return n
}

// seedRateLimitBucket ensures the fleet-wide token bucket row exists, seeding it
// from config on first run. ON CONFLICT DO NOTHING preserves any values an operator
// has since tuned via SQL.
func seedRateLimitBucket(ctx context.Context, st *store.Queries, logger *slog.Logger) {
	if st == nil {
		return
	}
	cfg := config.AppConfig()
	if !cfg.AppConf.DNSRateLimitEnabled {
		return
	}
	if err := st.RateLimitUpsertBucket(ctx, store.RateLimitUpsertBucketParams{
		Key:     dnsclient.RateLimitBucketKey,
		Tokens:  cfg.AppConf.DNSRateLimitBurst,
		RateQps: cfg.AppConf.DNSRateLimitQPS,
		Burst:   cfg.AppConf.DNSRateLimitBurst,
	}); err != nil {
		logger.Warn("failed to seed dns rate limit bucket", "error", err)
	}
}
