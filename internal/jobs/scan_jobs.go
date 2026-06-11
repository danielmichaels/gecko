package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jackc/pgx/v5"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/scanner"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/tracing"
	"github.com/riverqueue/river"
)

type ScanCertificateArgs struct {
	DomainJobArgs
}

func (ScanCertificateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanCertificateArgs) Kind() string { return "scan_certificate" }

type ScanCertificateWorker struct {
	river.WorkerDefaults[ScanCertificateArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *ScanCertificateWorker) Work(
	ctx context.Context,
	job *river.Job[ScanCertificateArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()

	s := scanner.NewScanner(scanner.Config{
		Logger:   &w.Logger,
		Store:    w.Store,
		Resolver: w.Resolver,
		Identity: job.Args.Identity(),
	})
	result := s.ScanCertificate(ctx, job.Args.DomainName)
	if result == nil {
		w.Logger.WarnContext(
			ctx,
			"certificate scan returned no certificate",
			"domain", job.Args.DomainName,
			"duration", time.Since(start),
		)
		return nil
	}
	w.Logger.InfoContext(
		ctx,
		"certificate scan complete",
		"domain", job.Args.DomainName,
		"duration", time.Since(start),
		"issuer", result.Issuer,
		"not_after", result.NotAfter,
		"tls_version", result.TLSVersion,
	)

	return enqueueAssessment(ctx, w.PgxPool, &w.Logger, job.Args.DomainUID,
		AssessCertificateArgs{DomainJobArgs: job.Args.DomainJobArgs})
}

type ScanCNAMEArgs struct {
	DomainJobArgs
}

func (ScanCNAMEArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanCNAMEArgs) Kind() string { return "scan_cname" }

type ScanCNAMEWorker struct {
	river.WorkerDefaults[ScanCNAMEArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *ScanCNAMEWorker) Work(ctx context.Context, job *river.Job[ScanCNAMEArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()

	s := scanner.NewScanner(scanner.Config{
		Logger:   &w.Logger,
		Store:    w.Store,
		Resolver: w.Resolver,
		Identity: job.Args.Identity(),
	})
	result := s.ScanCNAME(job.Args.DomainName)

	w.Logger.InfoContext(
		ctx,
		"cname scan complete",
		"domain", job.Args.DomainName,
		"duration", time.Since(start),
		"cname_count", len(result.CNAME),
	)

	return enqueueAssessment(ctx, w.PgxPool, &w.Logger, job.Args.DomainUID,
		AssessCNAMEDanglingArgs{DomainJobArgs: job.Args.DomainJobArgs})
}

type ScanDNSSECArgs struct {
	DomainJobArgs
}

func (ScanDNSSECArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanDNSSECArgs) Kind() string { return "scan_dnssec" }

type ScanDNSSECWorker struct {
	river.WorkerDefaults[ScanDNSSECArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *ScanDNSSECWorker) Work(ctx context.Context, job *river.Job[ScanDNSSECArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()

	s := scanner.NewScanner(scanner.Config{
		Logger:   &w.Logger,
		Store:    w.Store,
		Resolver: w.Resolver,
		Identity: job.Args.Identity(),
	})
	result := s.ScanDNSSEC(ctx, job.Args.DomainName)

	w.Logger.InfoContext(
		ctx,
		"dnssec scan complete",
		"domain", job.Args.DomainName,
		"duration", time.Since(start),
		"status", result.Status,
		"has_rrsig", result.HasRRSIG,
		"has_ds", result.HasDS,
		"has_dnskey", result.HasDNSKEY,
	)

	return enqueueAssessment(ctx, w.PgxPool, &w.Logger, job.Args.DomainUID,
		AssessDNSSECArgs{DomainJobArgs: job.Args.DomainJobArgs})
}

// enqueueAssessment inserts a follow-on assessment job in its own transaction so
// the scan and its downstream assessment are enqueued atomically.
func enqueueAssessment(
	ctx context.Context,
	pool *pgxpool.Pool,
	logger *slog.Logger,
	domainUID string,
	args river.JobArgs,
) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil {
				logger.Error("transaction rollback", "error", rbErr)
			}
		}
	}()
	rc := river.ClientFromContext[pgx.Tx](ctx)
	if _, err = rc.InsertTx(ctx, tx, args, nil); err != nil {
		logger.Error("failed to queue assessment job", "domain", domainUID, "error", err)
		return err
	}
	return tx.Commit(ctx)
}

type ScanZoneTransferArgs struct {
	DomainJobArgs
}

func (ScanZoneTransferArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanZoneTransferArgs) Kind() string { return "scan_zone_transfer" }

type ScanZoneTransferWorker struct {
	river.WorkerDefaults[ScanZoneTransferArgs]
	Logger   slog.Logger
	Store    *store.Queries
	PgxPool  *pgxpool.Pool
	Resolver dnsclient.Resolver
}

func (w *ScanZoneTransferWorker) Work(
	ctx context.Context,
	job *river.Job[ScanZoneTransferArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, false)
	start := time.Now()

	s := scanner.NewScanner(scanner.Config{
		Logger:   &w.Logger,
		Store:    w.Store,
		Resolver: w.Resolver,
		Identity: job.Args.Identity(),
	})
	if _, err := s.ScanZoneTransfer(ctx, job.Args.DomainName); err != nil {
		return err
	}

	w.Logger.InfoContext(
		ctx,
		"zone transfer scan complete",
		"domain", job.Args.DomainName,
		"duration", time.Since(start),
	)

	// todo: should we allow configuration to scan without auto assessing
	tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func(tx pgx.Tx, ctx context.Context) {
		if err != nil {
			err := tx.Rollback(ctx)
			if err != nil {
				w.Logger.Error("transaction rollback", "error", err)
			}
		}
	}(tx, ctx)
	rc := river.ClientFromContext[pgx.Tx](ctx)
	_, err = rc.InsertTx(
		ctx,
		tx,
		AssessZoneTransferArgs{DomainJobArgs: job.Args.DomainJobArgs},
		nil,
	)
	if err != nil {
		w.Logger.Error("failed to queue resolver job", "domain", job.Args.DomainUID, "error", err)
	}
	return tx.Commit(ctx)
}
