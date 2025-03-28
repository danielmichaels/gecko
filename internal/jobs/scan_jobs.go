package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jackc/pgx/v5"

	"github.com/danielmichaels/gecko/internal/scanner"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/tracing"
	"github.com/riverqueue/river"
)

type ScanCertificateArgs struct {
	Domain string `json:"domain"`
}

func (ScanCertificateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanCertificateArgs) Kind() string { return "scan_certificate" }

type ScanCertificateWorker struct {
	river.WorkerDefaults[ScanCertificateArgs]
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

func (w *ScanCertificateWorker) Work(
	ctx context.Context,
	job *river.Job[ScanCertificateArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()

	s := scanner.NewScanner(scanner.Config{Logger: &w.Logger, Store: w.Store})
	result := s.ScanCertificate(job.Args.Domain)
	w.Logger.InfoContext(ctx,
		"certificate scan complete",
		"domain", job.Args.Domain,
		"duration", time.Since(start),
	)
	fmt.Printf("Certificate scan complete for: %q\n%+v\n", job.Args.Domain, result)
	return nil
}

type ScanCNAMEArgs struct {
	Domain string `json:"domain"`
}

func (ScanCNAMEArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanCNAMEArgs) Kind() string { return "scan_cname" }

type ScanCNAMEWorker struct {
	river.WorkerDefaults[ScanCNAMEArgs]
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

func (w *ScanCNAMEWorker) Work(ctx context.Context, job *river.Job[ScanCNAMEArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()

	s := scanner.NewScanner(scanner.Config{Logger: &w.Logger, Store: w.Store})
	result := s.ScanCNAME(job.Args.Domain)

	w.Logger.InfoContext(ctx,
		"cname scan complete",
		"domain", job.Args.Domain,
		"duration", time.Since(start),
		"result", result, // remove, debugging only pre-alpha
	)
	rc := river.ClientFromContext[pgx.Tx](ctx)
	// todo: This isn't done inside a tx so we can't InsertTx easily.
	_, err := rc.Insert(ctx, &AssessCNAMEDanglingArgs{Domain: job.Args.Domain}, nil)
	if err != nil {
		return err
	}
	return nil
}

type ScanDNSSECArgs struct {
	Domain string `json:"domain"`
}

func (ScanDNSSECArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanDNSSECArgs) Kind() string { return "scan_dnssec" }

type ScanDNSSECWorker struct {
	river.WorkerDefaults[ScanDNSSECArgs]
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

func (w *ScanDNSSECWorker) Work(ctx context.Context, job *river.Job[ScanDNSSECArgs]) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()

	s := scanner.NewScanner(scanner.Config{Logger: &w.Logger, Store: w.Store})
	result := s.ScanDNSSEC(job.Args.Domain)

	w.Logger.InfoContext(ctx,
		"dnssec scan complete",
		"domain", job.Args.Domain,
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
	Domain string `json:"domain"`
}

func (ScanZoneTransferArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}
func (ScanZoneTransferArgs) Kind() string { return "scan_zone_transfer" }

type ScanZoneTransferWorker struct {
	river.WorkerDefaults[ScanZoneTransferArgs]
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

func (w *ScanZoneTransferWorker) Work(
	ctx context.Context,
	job *river.Job[ScanZoneTransferArgs],
) error {
	ctx = tracing.WithNewTraceID(ctx, true)
	start := time.Now()

	s := scanner.NewScanner(scanner.Config{Logger: &w.Logger, Store: w.Store})
	dUID, err := s.ScanZoneTransfer(ctx, job.Args.Domain)
	if err != nil {
		return err
	}

	w.Logger.InfoContext(ctx,
		"zone transfer scan complete",
		"domain", job.Args.Domain,
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
	_, err = rc.InsertTx(ctx, tx, AssessZoneTransferArgs{
		DomainUID: dUID,
	}, nil)
	if err != nil {
		w.Logger.Error("failed to queue resolver job", "domain", dUID, "error", err)
	}
	err = tx.Commit(ctx)
	return nil
}

type ScanNewDomainArgs struct {
	Domain string `json:"domain"`
}

func (ScanNewDomainArgs) Kind() string { return "new_domain_scanner" }
func (ScanNewDomainArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueScanner,
	}
}

type ScanNewDomainWorker struct {
	river.WorkerDefaults[ScanNewDomainArgs]
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
}

func (w *ScanNewDomainWorker) Work(ctx context.Context, job *river.Job[ScanNewDomainArgs]) error {
	tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func(tx pgx.Tx, ctx context.Context) {
		err := tx.Rollback(ctx)
		if err != nil {
			w.Logger.ErrorContext(ctx, "failed to rollback tx", "err", err)
		}
	}(tx, ctx)

	rc := river.ClientFromContext[pgx.Tx](ctx)

	if _, err := rc.InsertTx(ctx, tx, &ResolveDomainArgs{Domain: job.Args.Domain}, nil); err != nil {
		return err
	}
	if _, err := rc.InsertTx(ctx, tx, &ScanCertificateArgs{Domain: job.Args.Domain}, nil); err != nil {
		return err
	}
	if _, err := rc.InsertTx(ctx, tx, &ScanCNAMEArgs{Domain: job.Args.Domain}, nil); err != nil {
		return err
	}
	if _, err := rc.InsertTx(ctx, tx, &ScanDNSSECArgs{Domain: job.Args.Domain}, nil); err != nil {
		return err
	}
	if _, err := rc.InsertTx(ctx, tx, &ScanZoneTransferArgs{Domain: job.Args.Domain}, nil); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
