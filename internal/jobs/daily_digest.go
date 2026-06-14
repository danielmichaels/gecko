package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/mailer"
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

	sent := 0
	for _, t := range due {
		dispatched, err := w.digestOne(ctx, t, until)
		if err != nil {
			// One tenant's failure must not abort the batch; its watermark stays put
			// so the window is retried on the next eligible tick.
			w.Logger.ErrorContext(
				ctx,
				"daily digest failed",
				"error", err,
				"tenant_id", t.TenantID,
			)
			continue
		}
		if dispatched {
			sent++
		}
	}
	return sent, nil
}

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
) (dispatched bool, err error) {
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
		return false, fmt.Errorf("digest summary: %w", err)
	}

	summary, err := toDigestSummary(summaryRow)
	if err != nil {
		return false, err
	}

	// Empty window: advance the watermark (so we don't re-scan it) and send nothing.
	if summary.Total() == 0 {
		return false, w.advanceWatermark(ctx, w.Store, t.TenantID, until)
	}

	recipients, err := w.recipients(ctx, t.TenantID)
	if err != nil {
		return false, err
	}
	// Changes but nobody to tell: still advance the watermark so the next window
	// starts clean (recipients may be added before the next tick).
	if len(recipients) == 0 {
		return false, w.advanceWatermark(ctx, w.Store, t.TenantID, until)
	}

	// The high-impact section is opt-out per tenant. When off, suppress both the
	// itemized list and the summary count so the subject and body never mention it.
	var highImpact []notify.HighImpactItem
	if t.NotifyHighImpact {
		highImpact, err = w.highImpact(ctx, t.TenantID, since, until)
	} else {
		summary.HighImpact = 0
	}
	if err != nil {
		return false, err
	}

	tenant, err := w.Store.TenantGetByID(ctx, t.TenantID)
	if err != nil {
		return false, fmt.Errorf("get tenant: %w", err)
	}

	n := notify.RenderDailyDigest(tenant.Name, w.Conf.AppConf.PublicBaseURL, summary, highImpact)
	n.TenantID = t.TenantID

	tx, err := w.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && !errors.Is(rbErr, pgx.ErrTxClosed) {
				w.Logger.ErrorContext(ctx, "daily digest rollback", "error", rbErr)
			}
		}
	}()

	if err = w.Dispatcher.Dispatch(ctx, tx, w.enabledChannels(), n, recipients); err != nil {
		return false, fmt.Errorf("dispatch digest: %w", err)
	}
	if err = w.advanceWatermark(ctx, w.Store.WithTx(tx), t.TenantID, until); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
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

func (w *DailyDigestWorker) recipients(
	ctx context.Context,
	tenantID int32,
) ([]notify.Recipient, error) {
	rows, err := w.Store.UsersListDigestRecipientsByTenant(
		ctx,
		pgtype.Int4{Int32: tenantID, Valid: true},
	)
	if err != nil {
		return nil, fmt.Errorf("list recipients: %w", err)
	}
	out := make([]notify.Recipient, 0, len(rows))
	for _, r := range rows {
		out = append(out, notify.Recipient{Email: r.Email, Name: textOrEmpty(r.Name)})
	}
	return out, nil
}

func (w *DailyDigestWorker) highImpact(
	ctx context.Context,
	tenantID int32,
	since, until pgtype.Timestamptz,
) ([]notify.HighImpactItem, error) {
	rows, err := w.Store.ObservationsDigestHighImpactByTenant(
		ctx,
		store.ObservationsDigestHighImpactByTenantParams{
			TenantID: tenantID,
			Since:    since,
			Until:    until,
			RowLimit: int32(w.highImpactLimit()),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list high-impact: %w", err)
	}
	out := make([]notify.HighImpactItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, notify.HighImpactItem{
			DomainName: r.DomainName,
			EntityType: r.EntityType,
			ChangeType: r.ChangeType,
			Severity:   ifaceText(r.Severity),
			Status:     ifaceText(r.Status),
			ObservedAt: r.ObservedAt.Time,
		})
	}
	return out, nil
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

// ifaceText coerces a sqlc interface{} column (payload->>'x' projects as untyped
// text) to a string, tolerating a NULL (nil) value.
func ifaceText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func textOrEmpty(t pgtype.Text) string {
	if t.Valid {
		return t.String
	}
	return ""
}

// riverEmailEnqueuer satisfies notify.EmailEnqueuer by inserting a send_email job on
// the caller's transaction, reusing exactly the path riverScheduler.EnqueueEmail
// uses. The River client comes from context (populated inside a running worker), so
// the email channel stays decoupled from the client lifecycle.
type riverEmailEnqueuer struct{}

func (riverEmailEnqueuer) EnqueueEmail(ctx context.Context, tx pgx.Tx, msg mailer.Message) error {
	rc := river.ClientFromContext[pgx.Tx](ctx)
	if rc == nil {
		return errors.New("no river client in context")
	}
	_, err := rc.InsertTx(ctx, tx, SendEmailArgs{
		To:      msg.To,
		Subject: msg.Subject,
		HTML:    msg.HTML,
		Text:    msg.Text,
	}, nil)
	return err
}
