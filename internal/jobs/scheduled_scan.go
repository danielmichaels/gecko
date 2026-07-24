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

const defaultScheduledScanBatch = 100

type ScheduledScanArgs struct{}

func (ScheduledScanArgs) Kind() string { return "scheduled_scan" }

type ScheduledScanWorker struct {
	river.WorkerDefaults[ScheduledScanArgs]
	Logger     slog.Logger
	Store      *store.Queries
	PgxPool    *pgxpool.Pool
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
