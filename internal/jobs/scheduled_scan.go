package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
)

// defaultScheduledScanBatch caps how many due domains a single tick enqueues, so a
// burst of simultaneously-due domains can't thunder-herd queue_scanner. The rest
// stay due and are picked up on the next tick.
const defaultScheduledScanBatch = 100

// ScheduledScanArgs drives the periodic scheduled-scan sweep. It carries no
// payload: the job is a leader-singleton tick that asks the DB which domains are
// due. River runs PeriodicJobs once cluster-wide on the elected leader, so no
// extra uniqueness is needed.
type ScheduledScanArgs struct{}

func (ScheduledScanArgs) Kind() string { return "scheduled_scan" }

// ScheduledScanWorker enqueues a scan for every active domain whose scheduling
// cursor (next_scan_at) has come due. It is the recurring half of the monitor:
// the periodic tick finds due domains; EnqueueDomainScan's chokepoint advances
// each cursor, so a domain scanned here drops out of the next tick's due set.
type ScheduledScanWorker struct {
	river.WorkerDefaults[ScheduledScanArgs]
	Logger  slog.Logger
	Store   *store.Queries
	PgxPool *pgxpool.Pool
	// BatchLimit overrides the per-tick cap (defaults to defaultScheduledScanBatch).
	BatchLimit int
}

func (w *ScheduledScanWorker) Work(ctx context.Context, _ *river.Job[ScheduledScanArgs]) error {
	rc := river.ClientFromContext[pgx.Tx](ctx)
	n, err := w.EnqueueDueScans(ctx, rc)
	if err != nil {
		return err
	}
	if n > 0 {
		w.Logger.InfoContext(ctx, "scheduled scans enqueued", "count", n)
	}
	return nil
}

// EnqueueDueScans is the worker's testable core: Work supplies the River client
// from context, tests supply it directly (the client cannot be held on the worker
// struct because it is built from the worker set). It enqueues a scan for each due
// domain, batch-capped, and returns how many were enqueued. Each domain runs in
// its own transaction so one failure leaves the rest of the batch intact.
func (w *ScheduledScanWorker) EnqueueDueScans(
	ctx context.Context,
	rc *river.Client[pgx.Tx],
) (int, error) {
	limit := w.BatchLimit
	if limit <= 0 {
		limit = defaultScheduledScanBatch
	}
	due, err := w.Store.DomainsListDueForScan(ctx, int32(limit))
	if err != nil {
		return 0, fmt.Errorf("list due domains: %w", err)
	}

	enqueued := 0
	for _, d := range due {
		if err := w.scanOne(ctx, rc, d); err != nil {
			// One domain's failure must not abort the batch; it stays due and is
			// retried on the next tick.
			w.Logger.ErrorContext(
				ctx,
				"scheduled scan enqueue failed",
				"error", err,
				"domain", d.Name,
				"domain_id", d.ID,
			)
			continue
		}
		enqueued++
	}
	return enqueued, nil
}

// scanOne enqueues a single due domain's scheduled scan in its own transaction.
// The recency window is the domain's effective interval, a backstop atop the
// cursor advance and the per-domain advisory lock; Force is false (the scheduler
// respects recency). EnumerateSubdomains is left off: periodic re-enumeration is a
// heavier, separate concern, and discovered subdomains carry their own cursors.
func (w *ScheduledScanWorker) scanOne(
	ctx context.Context,
	rc *river.Client[pgx.Tx],
	d store.DomainsListDueForScanRow,
) (err error) {
	tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
				w.Logger.ErrorContext(ctx, "scheduled scan rollback", "error", rbErr)
			}
		}
	}()
	st := w.Store.WithTx(tx)

	window, _ := FrequencyInterval(d.EffectiveFrequency)
	if _, err = EnqueueDomainScan(ctx, rc, tx, st, DomainScanTarget{
		TenantID:   d.TenantID.Int32,
		DomainID:   d.ID,
		DomainUID:  d.Uid,
		DomainName: d.Name,
		Status:     d.Status,
	}, DomainScanOptions{
		Source:        store.ScanSourceScheduled,
		Force:         false,
		RecencyWindow: window,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
