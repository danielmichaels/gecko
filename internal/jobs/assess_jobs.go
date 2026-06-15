package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/assessor"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/tracing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/riverqueue/river"
)

type AssessCNAMEDanglingArgs struct {
	DomainJobArgs
}

func (AssessCNAMEDanglingArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessCNAMEDanglingArgs) Kind() string { return "assess_cname_dangling" }

type AssessCNAMEDanglingWorker struct {
	river.WorkerDefaults[AssessCNAMEDanglingArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *AssessCNAMEDanglingWorker) Work(
	ctx context.Context,
	job *river.Job[AssessCNAMEDanglingArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()
	w.Logger.InfoContext(ctx, "assess CNAME started", "domain", job.Args.DomainUID)
	a := assessor.NewAssessor(assessor.Config{
		Logger:    &w.Logger,
		Store:     w.Store,
		DNSClient: w.Resolver,
		Identity:  job.Args.Identity(),
	})
	if err := a.AssessCNAMEDangling(ctx, job.Args.DomainUID); err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"assess CNAME complete",
		"domain",
		job.Args.DomainUID,
		"duration",
		time.Since(start),
	)
	return nil
}

type AssessZoneTransferArgs struct {
	DomainJobArgs
}

func (AssessZoneTransferArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessZoneTransferArgs) Kind() string { return "assess_zone_transfer" }

type AssessZoneTransferWorker struct {
	river.WorkerDefaults[AssessZoneTransferArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *AssessZoneTransferWorker) Work(
	ctx context.Context,
	job *river.Job[AssessZoneTransferArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()
	w.Logger.InfoContext(ctx, "assess zone transfer started", "domain", job.Args.DomainUID)
	a := assessor.NewAssessor(assessor.Config{
		Logger:    &w.Logger,
		Store:     w.Store,
		DNSClient: w.Resolver,
		Identity:  job.Args.Identity(),
	})
	err := a.AssessZoneTransfer(ctx, job.Args.DomainUID)
	if err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"assess zone transfer complete",
		"domain",
		job.Args.DomainUID,
		"duration",
		time.Since(start),
	)
	return nil
}

type AssessEmailSecurityArgs struct {
	DomainJobArgs
}

func (AssessEmailSecurityArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessEmailSecurityArgs) Kind() string { return "assess_email_security" }

type AssessEmailSecurityWorker struct {
	river.WorkerDefaults[AssessEmailSecurityArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *AssessEmailSecurityWorker) Work(
	ctx context.Context,
	job *river.Job[AssessEmailSecurityArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()
	w.Logger.InfoContext(ctx, "assess email security started", "domain", job.Args.DomainUID)
	a := assessor.NewAssessor(assessor.Config{
		Logger:    &w.Logger,
		Store:     w.Store,
		DNSClient: w.Resolver,
		Identity:  job.Args.Identity(),
	})
	err := a.AssessEmailSecurity(ctx, int(job.Args.DomainID))
	if err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"assess email security complete",
		"domain",
		job.Args.DomainUID,
		"duration",
		time.Since(start),
	)
	return nil
}

type AssessCertificateArgs struct {
	DomainJobArgs
}

func (AssessCertificateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessCertificateArgs) Kind() string { return "assess_certificate" }

type AssessCertificateWorker struct {
	river.WorkerDefaults[AssessCertificateArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *AssessCertificateWorker) Work(
	ctx context.Context,
	job *river.Job[AssessCertificateArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()
	w.Logger.InfoContext(ctx, "assess certificate started", "domain", job.Args.DomainUID)
	a := assessor.NewAssessor(assessor.Config{
		Logger:    &w.Logger,
		Store:     w.Store,
		DNSClient: w.Resolver,
		Identity:  job.Args.Identity(),
	})
	if err := a.AssessCertificate(ctx, job.Args.DomainUID); err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"assess certificate complete",
		"domain",
		job.Args.DomainUID,
		"duration",
		time.Since(start),
	)
	return nil
}

type AssessDNSSECArgs struct {
	DomainJobArgs
}

func (AssessDNSSECArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessDNSSECArgs) Kind() string { return "assess_dnssec" }

type AssessDNSSECWorker struct {
	river.WorkerDefaults[AssessDNSSECArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *AssessDNSSECWorker) Work(
	ctx context.Context,
	job *river.Job[AssessDNSSECArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()
	w.Logger.InfoContext(ctx, "assess dnssec started", "domain", job.Args.DomainUID)
	a := assessor.NewAssessor(assessor.Config{
		Logger:    &w.Logger,
		Store:     w.Store,
		DNSClient: w.Resolver,
		Identity:  job.Args.Identity(),
	})
	if err := a.AssessDNSSEC(ctx, job.Args.DomainUID); err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"assess dnssec complete",
		"domain",
		job.Args.DomainUID,
		"duration",
		time.Since(start),
	)
	return nil
}

type AssessCAAArgs struct {
	DomainJobArgs
}

func (AssessCAAArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessCAAArgs) Kind() string { return "assess_caa" }

type AssessCAAWorker struct {
	river.WorkerDefaults[AssessCAAArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *AssessCAAWorker) Work(
	ctx context.Context,
	job *river.Job[AssessCAAArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()
	w.Logger.InfoContext(ctx, "assess caa started", "domain", job.Args.DomainUID)
	a := assessor.NewAssessor(assessor.Config{
		Logger:    &w.Logger,
		Store:     w.Store,
		DNSClient: w.Resolver,
		Identity:  job.Args.Identity(),
	})
	if err := a.AssessCAA(ctx, job.Args.DomainUID); err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"assess caa complete",
		"domain",
		job.Args.DomainUID,
		"duration",
		time.Since(start),
	)
	return nil
}

type AssessMinimumRecordSetArgs struct {
	DomainJobArgs
}

func (AssessMinimumRecordSetArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessMinimumRecordSetArgs) Kind() string { return "assess_minimum_record_set" }

type AssessMinimumRecordSetWorker struct {
	river.WorkerDefaults[AssessMinimumRecordSetArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *AssessMinimumRecordSetWorker) Work(
	ctx context.Context,
	job *river.Job[AssessMinimumRecordSetArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()
	w.Logger.InfoContext(ctx, "assess minimum record set started", "domain", job.Args.DomainUID)
	a := assessor.NewAssessor(assessor.Config{
		Logger:    &w.Logger,
		Store:     w.Store,
		DNSClient: w.Resolver,
		Identity:  job.Args.Identity(),
	})
	if err := a.AssessMinimumRecordSet(ctx, job.Args.DomainUID); err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"assess minimum record set complete",
		"domain",
		job.Args.DomainUID,
		"duration",
		time.Since(start),
	)
	return nil
}

type AssessNameserverConfigArgs struct {
	DomainJobArgs
}

func (AssessNameserverConfigArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueAssessor,
	}
}
func (AssessNameserverConfigArgs) Kind() string { return "assess_nameserver_config" }

type AssessNameserverConfigWorker struct {
	river.WorkerDefaults[AssessNameserverConfigArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *AssessNameserverConfigWorker) Work(
	ctx context.Context,
	job *river.Job[AssessNameserverConfigArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()
	w.Logger.InfoContext(ctx, "assess nameserver config started", "domain", job.Args.DomainUID)
	a := assessor.NewAssessor(assessor.Config{
		Logger:    &w.Logger,
		Store:     w.Store,
		DNSClient: w.Resolver,
		Identity:  job.Args.Identity(),
	})
	if err := a.AssessNameserverConfig(ctx, job.Args.DomainUID); err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"assess nameserver config complete",
		"domain",
		job.Args.DomainUID,
		"duration",
		time.Since(start),
	)
	return nil
}
