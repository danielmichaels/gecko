package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/mailer"
	"github.com/danielmichaels/gecko/internal/notify"
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
	Mailer      mailer.Mailer
	WorkerCount int
	AddWorkers  bool
}

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
		river.AddWorker(
			rw,
			&AssessCertificateWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&AssessDNSSECWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&AssessCAAWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&AssessMinimumRecordSetWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&AssessNameserverConfigWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&AssessNameserverHealthWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(
			rw,
			&AssessDanglingNSWorker{
				Logger:   *cfg.Logger,
				Store:    cfg.Store,
				PgxPool:  cfg.PgxPool,
				Resolver: cfg.Resolver,
			},
		)
		river.AddWorker(rw, &PurgeDNSCacheWorker{Logger: *cfg.Logger, Store: cfg.Store})
		river.AddWorker(rw, &RefreshTenantStatsWorker{Logger: *cfg.Logger, Store: cfg.Store})
		river.AddWorker(
			rw,
			&ScheduledScanWorker{Logger: *cfg.Logger, Store: cfg.Store, PgxPool: cfg.PgxPool},
		)
		river.AddWorker(
			rw,
			&DailyDigestWorker{
				Logger:     *cfg.Logger,
				Store:      cfg.Store,
				PgxPool:    cfg.PgxPool,
				Dispatcher: notify.NewDispatcher(notify.NewEmailChannel(riverEmailEnqueuer{})),
				Conf:       config.AppConfig(),
			},
		)
		river.AddWorker(
			rw,
			&HighImpactAlertWorker{
				Logger:     *cfg.Logger,
				Store:      cfg.Store,
				PgxPool:    cfg.PgxPool,
				Dispatcher: notify.NewDispatcher(notify.NewEmailChannel(riverEmailEnqueuer{})),
				Conf:       config.AppConfig(),
			},
		)
		emailerOut := cfg.Mailer
		if emailerOut == nil {
			emailerOut = &mailer.LogMailer{Logger: cfg.Logger}
		}
		river.AddWorker(rw, &SendEmailWorker{Logger: *cfg.Logger, Mailer: emailerOut})
		riverConfig.Workers = rw
		riverConfig.Middleware = []rivertype.Middleware{
			&CorrelationMiddleware{},
			&TimingMiddleware{Logger: cfg.Logger},
		}
		riverConfig.MaxAttempts = 5
		riverConfig.Queues = map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: cfg.WorkerCount},
			queueResolver:      {MaxWorkers: cfg.WorkerCount},
			queueEnumeration:   {MaxWorkers: enumerationWorkers(cfg.WorkerCount)},
			queueScanner:       {MaxWorkers: cfg.WorkerCount},
			queueAssessor:      {MaxWorkers: cfg.WorkerCount},
		}
		riverConfig.PeriodicJobs = []*river.PeriodicJob{
			river.NewPeriodicJob(
				river.PeriodicInterval(5*time.Minute),
				func() (river.JobArgs, *river.InsertOpts) {
					return RefreshTenantStatsArgs{}, nil
				},
				&river.PeriodicJobOpts{RunOnStart: true},
			),
			river.NewPeriodicJob(
				river.PeriodicInterval(1*time.Minute),
				func() (river.JobArgs, *river.InsertOpts) {
					return ScheduledScanArgs{}, nil
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
		if config.AppConfig().AppConf.NotifyDigestEnabled {
			riverConfig.PeriodicJobs = append(
				riverConfig.PeriodicJobs,
				river.NewPeriodicJob(
					river.PeriodicInterval(1*time.Hour),
					func() (river.JobArgs, *river.InsertOpts) {
						return DailyDigestArgs{}, nil
					},
					&river.PeriodicJobOpts{RunOnStart: false},
				),
			)
		}
		if config.AppConfig().AppConf.NotifyAlertsEnabled {
			riverConfig.PeriodicJobs = append(
				riverConfig.PeriodicJobs,
				river.NewPeriodicJob(
					river.PeriodicInterval(alertInterval()),
					func() (river.JobArgs, *river.InsertOpts) {
						return HighImpactAlertArgs{}, nil
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

func alertInterval() time.Duration {
	d := config.AppConfig().AppConf.NotifyAlertInterval
	if d <= 0 {
		return 10 * time.Minute
	}
	return d
}

func enumerationWorkers(fallback int) int {
	n := config.AppConfig().AppConf.EnumerationWorkerCount
	if n <= 0 {
		return fallback
	}
	return n
}

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
