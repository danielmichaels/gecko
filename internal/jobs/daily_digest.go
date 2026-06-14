package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/notify"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
)

// defaultHighImpactLimit caps how many high-impact items the digest itemizes when
// config does not set one.
const defaultHighImpactLimit = 50

// DailyDigestArgs drives the daily notification digest. Like ScheduledScanArgs it
// carries no payload: River runs PeriodicJobs once cluster-wide on the elected
// leader, so the tick is a leader-singleton with no extra uniqueness needed.
type DailyDigestArgs struct{}

func (DailyDigestArgs) Kind() string { return "daily_digest" }

// DailyDigestWorker sends a per-tenant summary of changes detected since each
// tenant's last digest, across that tenant's enabled channels. It is the recurring
// notification half of the monitor: the periodic tick finds tenants with changes in
// the window (last_digest_at, now] and the watermark advance — committed in the same
// transaction as the channel enqueues — moves each tenant's window forward so the
// same change is never reported twice.
type DailyDigestWorker struct {
	river.WorkerDefaults[DailyDigestArgs]
	Logger     slog.Logger
	Store      *store.Queries
	PgxPool    *pgxpool.Pool
	Dispatcher *notify.Dispatcher
	Conf       *config.Conf
	// Channels names the bearers a digest is dispatched across. Defaults to email.
	Channels []string
}

func (w *DailyDigestWorker) Work(ctx context.Context, _ *river.Job[DailyDigestArgs]) error {
	// The job ticks hourly; do work only on the configured send hour. The per-tenant
	// watermark prevents a second send within the same day even if this hour's tick
	// runs more than once.
	if time.Now().UTC().Hour() != w.sendHour() {
		return nil
	}
	n, err := w.EnqueueDueDigests(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		w.Logger.InfoContext(ctx, "daily digests sent", "count", n)
	}
	return nil
}

// EnqueueDueDigests is the worker's testable core: it dispatches a digest for each
// opted-in tenant that had changes in its window, advances every processed tenant's
// watermark, and returns how many digests were dispatched. Each tenant runs in its
// own transaction so one tenant's failure leaves the rest of the batch intact. The
// email channel enqueues its send_email jobs via the River client carried on ctx, so
// no client is threaded here.
func (w *DailyDigestWorker) EnqueueDueDigests(ctx context.Context) (int, error) {
	// Captured once: this is the new watermark and the window's upper bound, so an
	// observation that lands mid-batch is reported in exactly one digest.
	now := time.Now()
	until := pgtype.Timestamptz{Time: now, Valid: true}

	due, err := w.Store.TenantsListDigestDue(ctx)
	if err != nil {
		return 0, fmt.Errorf("list digest-due tenants: %w", err)
	}

	var sent, empty, noRecipients, failed int
	for _, t := range due {
		outcome, err := w.digestOne(ctx, t, until)
		if err != nil {
			// One tenant's failure must not abort the batch; its watermark stays put
			// so the window is retried on the next eligible tick.
			failed++
			w.Logger.ErrorContext(
				ctx,
				"daily digest failed",
				"error", err,
				"tenant_id", t.TenantID,
			)
			continue
		}
		switch outcome {
		case digestDispatched:
			sent++
		case digestSkippedEmpty:
			empty++
		case digestSkippedNoRecipients:
			noRecipients++
		}
	}
	w.Logger.InfoContext(
		ctx,
		"daily digest sweep complete",
		"tenants", len(due),
		"sent", sent,
		"skipped_empty", empty,
		"skipped_no_recipients", noRecipients,
		"failed", failed,
	)
	return sent, nil
}

// digestOutcome records what happened for one tenant in a digest sweep, so the
// sweep can tally per-reason counts for observability.
type digestOutcome int

const (
	digestDispatched digestOutcome = iota
	digestSkippedEmpty
	digestSkippedNoRecipients
)

// digestOne processes a single tenant: it reads the change summary for the window,
// and — when there are changes and recipients — renders and dispatches the digest
// across the enabled channels, advancing the watermark in the same transaction.
// Returns whether a digest was actually dispatched (false when the window was empty
// or the tenant has no recipients; the watermark still advances in those cases so
// the empty window is not re-scanned).
func (w *DailyDigestWorker) digestOne(
	ctx context.Context,
	t store.TenantsListDigestDueRow,
	until pgtype.Timestamptz,
) (outcome digestOutcome, err error) {
	since := t.NotificationsLastDigestAt
	if !since.Valid {
		// Never sent: bound the first digest to the fallback window rather than the
		// tenant's whole history.
		since = pgtype.Timestamptz{
			Time:  until.Time.Add(-w.fallbackWindow()),
			Valid: true,
		}
	}

	summaryRow, err := w.Store.ObservationsDigestSummaryByTenant(
		ctx,
		store.ObservationsDigestSummaryByTenantParams{
			TenantID: t.TenantID,
			Since:    since,
			Until:    until,
		},
	)
	if err != nil {
		return digestSkippedEmpty, fmt.Errorf("digest summary: %w", err)
	}

	summary, err := toDigestSummary(summaryRow)
	if err != nil {
		return digestSkippedEmpty, err
	}

	// Empty window: advance the watermark (so we don't re-scan it) and send nothing.
	if summary.Total() == 0 {
		return digestSkippedEmpty, w.advanceWatermark(ctx, w.Store, t.TenantID, until)
	}

	recipients, err := loadDigestRecipients(ctx, w.Store, t.TenantID)
	if err != nil {
		return digestSkippedEmpty, err
	}
	// Changes but nobody to tell: still advance the watermark so the next window
	// starts clean (recipients may be added before the next tick).
	if len(recipients) == 0 {
		return digestSkippedNoRecipients, w.advanceWatermark(ctx, w.Store, t.TenantID, until)
	}

	// The high-impact section is opt-out per tenant. When off, suppress both the
	// itemized list and the summary count so the subject and body never mention it.
	var highImpact []notify.HighImpactItem
	if t.NotifyHighImpact {
		highImpact, err = loadHighImpactItems(
			ctx,
			w.Store,
			t.TenantID,
			since,
			until,
			w.highImpactLimit(),
		)
	} else {
		summary.HighImpact = 0
	}
	if err != nil {
		return digestSkippedEmpty, err
	}

	tenant, err := w.Store.TenantGetByID(ctx, t.TenantID)
	if err != nil {
		return digestSkippedEmpty, fmt.Errorf("get tenant: %w", err)
	}

	n := notify.RenderDailyDigest(tenant.Name, w.Conf.AppConf.PublicBaseURL, summary, highImpact)
	n.TenantID = t.TenantID

	tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return digestSkippedEmpty, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
				w.Logger.ErrorContext(ctx, "daily digest rollback", "error", rbErr)
			}
		}
	}()

	if err = w.Dispatcher.Dispatch(ctx, tx, w.enabledChannels(), n, recipients); err != nil {
		return digestSkippedEmpty, fmt.Errorf("dispatch digest: %w", err)
	}
	if err = w.advanceWatermark(ctx, w.Store.WithTx(tx), t.TenantID, until); err != nil {
		return digestSkippedEmpty, err
	}
	if err = tx.Commit(ctx); err != nil {
		return digestSkippedEmpty, fmt.Errorf("commit: %w", err)
	}
	return digestDispatched, nil
}

func (w *DailyDigestWorker) advanceWatermark(
	ctx context.Context,
	q *store.Queries,
	tenantID int32,
	until pgtype.Timestamptz,
) error {
	if err := q.NotificationDigestAdvanceWatermark(ctx, store.NotificationDigestAdvanceWatermarkParams{
		SentAt:   until,
		TenantID: tenantID,
	}); err != nil {
		return fmt.Errorf("advance watermark: %w", err)
	}
	return nil
}

func (w *DailyDigestWorker) enabledChannels() []string {
	if len(w.Channels) > 0 {
		return w.Channels
	}
	return []string{"email"}
}

func (w *DailyDigestWorker) sendHour() int {
	if w.Conf == nil {
		return 8
	}
	return w.Conf.AppConf.NotifyDigestHour
}

func (w *DailyDigestWorker) fallbackWindow() time.Duration {
	if w.Conf == nil || w.Conf.AppConf.NotifyDigestFallbackWindow <= 0 {
		return 24 * time.Hour
	}
	return w.Conf.AppConf.NotifyDigestFallbackWindow
}

func (w *DailyDigestWorker) highImpactLimit() int {
	if w.Conf == nil || w.Conf.AppConf.NotifyHighImpactLimit <= 0 {
		return defaultHighImpactLimit
	}
	return w.Conf.AppConf.NotifyHighImpactLimit
}

// toDigestSummary maps the store summary row into the notify model, decoding the
// jsonb breakdown emitted by the aggregate query.
func toDigestSummary(row store.ObservationsDigestSummaryByTenantRow) (notify.DigestSummary, error) {
	s := notify.DigestSummary{
		Created:    int(row.CreatedCount),
		Updated:    int(row.UpdatedCount),
		Deleted:    int(row.DeletedCount),
		HighImpact: int(row.HighImpactCount),
	}
	b, ok := row.Breakdown.([]byte)
	if !ok || len(b) == 0 {
		return s, nil
	}
	var items []struct {
		EntityType string `json:"entity_type"`
		ChangeType string `json:"change_type"`
		Count      int    `json:"count"`
	}
	if err := json.Unmarshal(b, &items); err != nil {
		return s, fmt.Errorf("unmarshal breakdown: %w", err)
	}
	for _, it := range items {
		s.Breakdown = append(s.Breakdown, notify.BreakdownItem{
			EntityType: it.EntityType,
			ChangeType: it.ChangeType,
			Count:      it.Count,
		})
	}
	return s, nil
}

// toDigestSummary is defined above; the shared recipient/high-impact loaders and the
// riverEmailEnqueuer live in notification_shared.go.
