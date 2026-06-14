package jobs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

// enableAlerts creates the tenant_settings row with the high-impact alert toggle set
// and the alert watermark planted in the past.
func enableAlerts(
	t *testing.T,
	ctx context.Context,
	q *store.Queries,
	tenantID int32,
	on bool,
	watermark time.Time,
) {
	t.Helper()
	if _, err := q.NotificationSettingsUpsert(ctx, store.NotificationSettingsUpsertParams{
		TenantID:               tenantID,
		NotifyDailyDigest:      false,
		NotifyHighImpact:       false,
		NotifyHighImpactAlerts: on,
	}); err != nil {
		t.Fatalf("upsert settings: %v", err)
	}
	if err := q.NotificationAlertAdvanceWatermark(ctx, store.NotificationAlertAdvanceWatermarkParams{
		SentAt:   pgtype.Timestamptz{Time: watermark, Valid: true},
		TenantID: tenantID,
	}); err != nil {
		t.Fatalf("set alert watermark: %v", err)
	}
}

func alertTestWorker(
	q *store.Queries,
	pc *testhelpers.PostgresContainer,
	enq *fakeEmailEnqueuer,
) *HighImpactAlertWorker {
	w := digestTestWorker(q, pc, enq)
	return &HighImpactAlertWorker{
		Logger:     w.Logger,
		Store:      w.Store,
		PgxPool:    w.PgxPool,
		Dispatcher: w.Dispatcher,
		Conf:       w.Conf,
	}
}

// TestHighImpactAlertWorker_EnqueueDueAlerts verifies the sweep alerts only opted-in
// tenants that have a critical/high finding in the window, never fires on
// medium-severity changes, excludes opted-out recipients, and advances the alert
// watermark so the same finding is not re-alerted.
func TestHighImpactAlertWorker_EnqueueDueAlerts(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)
	q := pc.Queries

	past := time.Now().Add(-30 * time.Minute)

	// Tenant A: alerts on, a critical finding, two recipients (one opted out).
	tenantA := seedStatsTenant(t, ctx, q, "owner@a.alert.test")
	enableAlerts(t, ctx, q, tenantA, true, past)
	domA := seedStatsDomain(t, ctx, q, tenantA, "a.alert.test")
	seedRecipient(t, ctx, q, tenantA, "owner@a.alert.test", store.UserRoleOwner)
	seedRecipient(t, ctx, q, tenantA, "mgr@a.alert.test", store.UserRoleManager)
	optOut(t, ctx, pc, tenantA, "mgr@a.alert.test")
	seedObservation(t, ctx, pc, tenantA, domA, "a.alert.test",
		"dangling_cname_finding", "created", `{"severity":"critical","status":"open"}`)

	// Tenant B: alerts on, but only a medium-severity change — must not alert.
	tenantB := seedStatsTenant(t, ctx, q, "owner@b.alert.test")
	enableAlerts(t, ctx, q, tenantB, true, past)
	domB := seedStatsDomain(t, ctx, q, tenantB, "b.alert.test")
	seedRecipient(t, ctx, q, tenantB, "owner@b.alert.test", store.UserRoleOwner)
	seedObservation(t, ctx, pc, tenantB, domB, "b.alert.test",
		"spf_finding", "updated", `{"severity":"medium","status":"open"}`)

	// Tenant C: alerts OFF, has a critical finding — must be skipped entirely.
	tenantC := seedStatsTenant(t, ctx, q, "owner@c.alert.test")
	enableAlerts(t, ctx, q, tenantC, false, past)
	domC := seedStatsDomain(t, ctx, q, tenantC, "c.alert.test")
	seedRecipient(t, ctx, q, tenantC, "owner@c.alert.test", store.UserRoleOwner)
	seedObservation(t, ctx, pc, tenantC, domC, "c.alert.test",
		"dangling_cname_finding", "created", `{"severity":"high","status":"open"}`)

	enq := &fakeEmailEnqueuer{}
	w := alertTestWorker(q, pc, enq)

	n, err := w.EnqueueDueAlerts(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueAlerts: %v", err)
	}
	if n != 1 {
		t.Errorf("alerts dispatched = %d, want 1 (only tenant A)", n)
	}

	// Only the non-opted-out owner of A is mailed.
	if len(enq.msgs) != 1 {
		t.Fatalf("emails = %d, want 1 (owner of A; manager opted out)", len(enq.msgs))
	}
	m := enq.msgs[0]
	if m.To != "owner@a.alert.test" {
		t.Errorf("recipient = %q, want owner@a.alert.test", m.To)
	}
	if !strings.Contains(m.Subject, "high-impact") {
		t.Errorf("alert subject = %q, want it to mention high-impact", m.Subject)
	}
	if !strings.Contains(m.HTML, "a.alert.test") || !strings.Contains(m.HTML, "critical") {
		t.Errorf("alert body missing the finding:\n%s", m.HTML)
	}

	// Watermarks for the processed tenants advanced past the seed; C (off) untouched.
	if wm := alertWatermarkOf(t, ctx, q, tenantA); !wm.Valid || !wm.Time.After(past) {
		t.Errorf("tenant A alert watermark = %v, want advanced", wm.Time)
	}
	if wm := alertWatermarkOf(t, ctx, q, tenantB); !wm.Valid || !wm.Time.After(past) {
		t.Errorf(
			"tenant B alert watermark = %v, want advanced (medium-only still advances)",
			wm.Time,
		)
	}
	if wm := alertWatermarkOf(t, ctx, q, tenantC); !wm.Valid ||
		wm.Time.After(past.Add(time.Second)) {
		t.Errorf("tenant C alert watermark = %v, want unchanged (alerts off)", wm.Time)
	}

	// Rerun: A's finding is now behind the watermark, so nothing re-alerts.
	enq2 := &fakeEmailEnqueuer{}
	w.Dispatcher = alertTestWorker(q, pc, enq2).Dispatcher
	n2, err := w.EnqueueDueAlerts(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueAlerts rerun: %v", err)
	}
	if n2 != 0 || len(enq2.msgs) != 0 {
		t.Errorf("rerun dispatched=%d emails=%d, want 0/0 (watermark advanced)", n2, len(enq2.msgs))
	}
}

func optOut(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	tenantID int32,
	email string,
) {
	t.Helper()
	if _, err := pc.Pool.Exec(
		ctx,
		`UPDATE users SET notify_opt_out = true WHERE tenant_id = $1 AND email = $2`,
		tenantID, email,
	); err != nil {
		t.Fatalf("opt out %s: %v", email, err)
	}
}

func alertWatermarkOf(
	t *testing.T,
	ctx context.Context,
	q *store.Queries,
	tenantID int32,
) pgtype.Timestamptz {
	t.Helper()
	row, err := q.NotificationSettingsGet(ctx, tenantID)
	if err != nil {
		t.Fatalf("get notification settings: %v", err)
	}
	return row.NotificationsLastAlertAt
}
