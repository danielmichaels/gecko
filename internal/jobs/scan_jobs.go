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

	s := scanner.NewScanner(scanner.Config{Logger: &w.Logger, Store: w.Store, Resolver: w.Resolver})
	result := s.ScanCertificate(job.Args.DomainName)
	w.Logger.InfoContext(
		ctx,
		"certificate scan complete",
		"domain", job.Args.DomainName,
		"duration", time.Since(start),
	)
	fmt.Printf("Certificate scan complete for: %q\n%+v\n", job.Args.DomainName, result)
	return nil
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

	s := scanner.NewScanner(scanner.Config{Logger: &w.Logger, Store: w.Store, Resolver: w.Resolver})
	result := s.ScanCNAME(job.Args.DomainName)

	w.Logger.InfoContext(
		ctx,
		"cname scan complete",
		"domain", job.Args.DomainName,
		"duration", time.Since(start),
		"result", result, // remove, debugging only pre-alpha
	)
	rc := river.ClientFromContext[pgx.Tx](ctx)
	// todo: This isn't done inside a tx so we can't InsertTx easily.
	_, err := rc.Insert(ctx, &AssessCNAMEDanglingArgs{DomainJobArgs: job.Args.DomainJobArgs}, nil)
	if err != nil {
		return err
	}
	return nil
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

	s := scanner.NewScanner(scanner.Config{Logger: &w.Logger, Store: w.Store, Resolver: w.Resolver})
	result := s.ScanDNSSEC(job.Args.DomainName)

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
	// todo: do something with the result
	return nil
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
