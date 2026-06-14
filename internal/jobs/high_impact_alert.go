package jobs

import (
	"context"
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

// HighImpactAlertArgs drives the near-real-time high-impact alert sweep. Like the
// digest it is a leader-singleton periodic tick with no payload.
//
// "Near-real-time" rather than instant by design: a frequent periodic sweep keyed on
// a per-tenant watermark is durable (a missed tick just widens the next window) and
// reuses the digest's watermark/dispatcher machinery, where a LISTEN/NOTIFY consumer
// would need its own reconnect and missed-event handling. The trade-off is up to one
// tick of latency.
type HighImpactAlertArgs struct{}

func (HighImpactAlertArgs) Kind() string { return "high_impact_alert" }

// HighImpactAlertWorker emails opted-in tenants the moment (within one tick) a
// critical/high-severity finding appears, separate from the daily digest. It is
// gated by the tenant's notify_high_impact_alerts toggle and tracked by its own
// watermark, so the alert and digest cadences never interfere.
type HighImpactAlertWorker struct {
	river.WorkerDefaults[HighImpactAlertArgs]
	Logger     slog.Logger
	Store      *store.Queries
	PgxPool    *pgxpool.Pool
	Dispatcher *notify.Dispatcher
	Conf       *config.Conf
	// Channels names the bearers an alert is dispatched across. Defaults to email.
	Channels []string
}

func (w *HighImpactAlertWorker) Work(ctx context.Context, _ *river.Job[HighImpactAlertArgs]) error {
	n, err := w.EnqueueDueAlerts(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		w.Logger.InfoContext(ctx, "high-impact alerts sent", "count", n)
	}
	return nil
}

// EnqueueDueAlerts is the worker's testable core: it dispatches an alert for each
// opted-in tenant that had a critical/high finding in its window, advances every
// processed tenant's alert watermark, and returns how many alerts were dispatched.
// Each tenant runs in its own transaction so one failure leaves the batch intact.
func (w *HighImpactAlertWorker) EnqueueDueAlerts(ctx context.Context) (int, error) {
	now := time.Now()
	until := pgtype.Timestamptz{Time: now, Valid: true}

	due, err := w.Store.TenantsListAlertDue(ctx)
	if err != nil {
		return 0, fmt.Errorf("list alert-due tenants: %w", err)
	}

	var sent, empty, noRecipients, failed int
	for _, t := range due {
		dispatched, err := w.alertOne(ctx, t, until)
		if err != nil {
			failed++
			w.Logger.ErrorContext(
				ctx,
				"high-impact alert failed",
				"error",
				err,
				"tenant_id",
				t.TenantID,
			)
			continue
		}
		switch dispatched {
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
		"high-impact alert sweep complete",
		"tenants", len(due),
		"sent", sent,
		"skipped_empty", empty,
		"skipped_no_recipients", noRecipients,
		"failed", failed,
	)
	return sent, nil
}

func (w *HighImpactAlertWorker) alertOne(
	ctx context.Context,
	t store.TenantsListAlertDueRow,
	until pgtype.Timestamptz,
) (outcome digestOutcome, err error) {
	since := t.NotificationsLastAlertAt
	if !since.Valid {
		since = pgtype.Timestamptz{Time: until.Time.Add(-w.fallbackWindow()), Valid: true}
	}

	items, err := loadHighImpactItems(ctx, w.Store, t.TenantID, since, until, w.highImpactLimit())
	if err != nil {
		return digestSkippedEmpty, err
	}
	// No high-impact findings in the window: advance the watermark and send nothing.
	if len(items) == 0 {
		return digestSkippedEmpty, w.advanceAlertWatermark(ctx, w.Store, t.TenantID, until)
	}

	recipients, err := loadDigestRecipients(ctx, w.Store, t.TenantID)
	if err != nil {
		return digestSkippedEmpty, err
	}
	if len(recipients) == 0 {
		return digestSkippedNoRecipients, w.advanceAlertWatermark(ctx, w.Store, t.TenantID, until)
	}

	tenant, err := w.Store.TenantGetByID(ctx, t.TenantID)
	if err != nil {
		return digestSkippedEmpty, fmt.Errorf("get tenant: %w", err)
	}

	n := notify.RenderHighImpactAlert(tenant.Name, w.Conf.AppConf.PublicBaseURL, items)
	n.TenantID = t.TenantID

	tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return digestSkippedEmpty, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
				w.Logger.ErrorContext(ctx, "high-impact alert rollback", "error", rbErr)
			}
		}
	}()

	if err = w.Dispatcher.Dispatch(ctx, tx, w.enabledChannels(), n, recipients); err != nil {
		return digestSkippedEmpty, fmt.Errorf("dispatch alert: %w", err)
	}
	if err = w.advanceAlertWatermark(ctx, w.Store.WithTx(tx), t.TenantID, until); err != nil {
		return digestSkippedEmpty, err
	}
	if err = tx.Commit(ctx); err != nil {
		return digestSkippedEmpty, fmt.Errorf("commit: %w", err)
	}
	return digestDispatched, nil
}

func (w *HighImpactAlertWorker) advanceAlertWatermark(
	ctx context.Context,
	q *store.Queries,
	tenantID int32,
	until pgtype.Timestamptz,
) error {
	if err := q.NotificationAlertAdvanceWatermark(ctx, store.NotificationAlertAdvanceWatermarkParams{
		SentAt:   until,
		TenantID: tenantID,
	}); err != nil {
		return fmt.Errorf("advance alert watermark: %w", err)
	}
	return nil
}

func (w *HighImpactAlertWorker) enabledChannels() []string {
	if len(w.Channels) > 0 {
		return w.Channels
	}
	return []string{"email"}
}

func (w *HighImpactAlertWorker) fallbackWindow() time.Duration {
	if w.Conf == nil || w.Conf.AppConf.NotifyAlertFallbackWindow <= 0 {
		return time.Hour
	}
	return w.Conf.AppConf.NotifyAlertFallbackWindow
}

func (w *HighImpactAlertWorker) highImpactLimit() int {
	if w.Conf == nil || w.Conf.AppConf.NotifyHighImpactLimit <= 0 {
		return defaultHighImpactLimit
	}
	return w.Conf.AppConf.NotifyHighImpactLimit
}
