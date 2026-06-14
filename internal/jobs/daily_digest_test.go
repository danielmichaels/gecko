package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/mailer"
	"github.com/danielmichaels/gecko/internal/notify"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// fakeEmailEnqueuer records the emails the digest dispatches, standing in for the
// River send_email path so the worker can be exercised without a live client.
type fakeEmailEnqueuer struct {
	msgs []mailer.Message
}

func (f *fakeEmailEnqueuer) EnqueueEmail(_ context.Context, _ pgx.Tx, msg mailer.Message) error {
	f.msgs = append(f.msgs, msg)
	return nil
}

func digestTestWorker(
	q *store.Queries,
	pc *testhelpers.PostgresContainer,
	enq notify.EmailEnqueuer,
) *DailyDigestWorker {
	cfg := config.AppConfig()
	cfg.AppConf.NotifyDigestFallbackWindow = 24 * time.Hour
	cfg.AppConf.PublicBaseURL = "https://app.gecko.test"
	return &DailyDigestWorker{
		Logger:     *testhelpers.TestLogger,
		Store:      q,
		PgxPool:    pc.Pool,
		Dispatcher: notify.NewDispatcher(notify.NewEmailChannel(enq)),
		Conf:       cfg,
	}
}

func seedRecipient(
	t *testing.T,
	ctx context.Context,
	q *store.Queries,
	tenantID int32,
	email string,
	role store.UserRole,
) {
	t.Helper()
	if _, err := q.UserProvision(ctx, store.UserProvisionParams{
		TenantID: pgtype.Int4{Int32: tenantID, Valid: true},
		Email:    email,
		Role:     role,
	}); err != nil {
		t.Fatalf("provision user %s: %v", email, err)
	}
}

// enableDigest creates the tenant_settings row with the digest toggle set and the
// watermark planted in the past so freshly-seeded observations fall inside the
// window.
func enableDigest(
	t *testing.T,
	ctx context.Context,
	q *store.Queries,
	tenantID int32,
	on bool,
	watermark time.Time,
) {
	t.Helper()
	if _, err := q.NotificationSettingsUpsert(ctx, store.NotificationSettingsUpsertParams{
		TenantID:          tenantID,
		NotifyDailyDigest: on,
		NotifyHighImpact:  true,
	}); err != nil {
		t.Fatalf("upsert notification settings: %v", err)
	}
	if err := q.NotificationDigestAdvanceWatermark(ctx, store.NotificationDigestAdvanceWatermarkParams{
		SentAt:   pgtype.Timestamptz{Time: watermark, Valid: true},
		TenantID: tenantID,
	}); err != nil {
		t.Fatalf("set watermark: %v", err)
	}
}

// seedObservation inserts an observation with an explicit in-window observed_at
// (a minute in the past). domain_observations.observed_at is TIMESTAMP(0), which
// Postgres *rounds* to the nearest second — a default now() could round up past the
// worker's sub-second upper bound and defer the row to the next window (correct in
// production, but flaky for a test that expects it this window). A fixed past stamp
// removes that ambiguity.
func seedObservation(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	tenantID, domainID int32,
	domainName, entityType, changeType, payload string,
) {
	t.Helper()
	const q = `INSERT INTO domain_observations
	    (tenant_id, domain_id, domain_uid, domain_name, entity_type, entity_key,
	     change_type, payload, observed_at)
	    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() - interval '1 minute')`
	if _, err := pc.Pool.Exec(
		ctx, q,
		tenantID,
		pgtype.Int4{Int32: domainID, Valid: true},
		"dom_"+domainName,
		domainName,
		entityType,
		entityType+":"+domainName,
		changeType,
		[]byte(payload),
	); err != nil {
		t.Fatalf("seed observation (%s/%s): %v", entityType, changeType, err)
	}
}

func watermarkOf(
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
	return row.NotificationsLastDigestAt
}

// TestDailyDigestWorker_EnqueueDueDigests verifies the worker dispatches a digest
// only for opted-in tenants that had changes in the window, fans out one email per
// active owner/manager, advances every processed tenant's watermark, and never
// touches a tenant whose digest toggle is off.
func TestDailyDigestWorker_EnqueueDueDigests(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)
	q := pc.Queries

	past := time.Now().Add(-1 * time.Hour)

	// Tenant A: opted in, has changes (incl. one high-impact), two recipients.
	tenantA := seedStatsTenant(t, ctx, q, "owner@a.digest.test")
	enableDigest(t, ctx, q, tenantA, true, past)
	domA := seedStatsDomain(t, ctx, q, tenantA, "a.digest.test")
	seedRecipient(t, ctx, q, tenantA, "owner@a.digest.test", store.UserRoleOwner)
	seedRecipient(t, ctx, q, tenantA, "mgr@a.digest.test", store.UserRoleManager)
	seedRecipient(t, ctx, q, tenantA, "viewer@a.digest.test", store.UserRoleViewer) // excluded
	seedObservation(
		t,
		ctx,
		pc,
		tenantA,
		domA,
		"a.digest.test",
		"a_record",
		"created",
		`{"ipv4_address":"1.2.3.4"}`,
	)
	seedObservation(
		t,
		ctx,
		pc,
		tenantA,
		domA,
		"a.digest.test",
		"dangling_cname_finding",
		"created",
		`{"severity":"critical","status":"open"}`,
	)

	// Tenant B: opted in, NO changes in the window.
	tenantB := seedStatsTenant(t, ctx, q, "owner@b.digest.test")
	enableDigest(t, ctx, q, tenantB, true, past)
	seedRecipient(t, ctx, q, tenantB, "owner@b.digest.test", store.UserRoleOwner)

	// Tenant C: digest OFF, has changes — must be skipped entirely.
	tenantC := seedStatsTenant(t, ctx, q, "owner@c.digest.test")
	enableDigest(t, ctx, q, tenantC, false, past)
	domC := seedStatsDomain(t, ctx, q, tenantC, "c.digest.test")
	seedRecipient(t, ctx, q, tenantC, "owner@c.digest.test", store.UserRoleOwner)
	seedObservation(
		t,
		ctx,
		pc,
		tenantC,
		domC,
		"c.digest.test",
		"mx_record",
		"updated",
		`{"target":"mx.c"}`,
	)

	enq := &fakeEmailEnqueuer{}
	w := digestTestWorker(q, pc, enq)

	n, err := w.EnqueueDueDigests(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueDigests: %v", err)
	}
	if n != 1 {
		t.Errorf("dispatched digests = %d, want 1 (only tenant A)", n)
	}

	// Tenant A: one email to the owner + one to the manager; viewer excluded.
	if len(enq.msgs) != 2 {
		t.Fatalf("emails = %d, want 2 (owner + manager of tenant A)", len(enq.msgs))
	}
	got := map[string]bool{}
	for _, m := range enq.msgs {
		got[m.To] = true
	}
	if !got["owner@a.digest.test"] || !got["mgr@a.digest.test"] {
		t.Errorf("recipients = %v, want owner+manager of A", got)
	}
	if got["viewer@a.digest.test"] {
		t.Error("viewer received a digest, want excluded")
	}

	// Watermarks: A and B advanced past the old watermark; C (off) untouched.
	if wm := watermarkOf(t, ctx, q, tenantA); !wm.Valid || !wm.Time.After(past) {
		t.Errorf("tenant A watermark = %v, want advanced past %v", wm.Time, past)
	}
	if wm := watermarkOf(t, ctx, q, tenantB); !wm.Valid || !wm.Time.After(past) {
		t.Errorf("tenant B watermark = %v, want advanced (empty window still advances)", wm.Time)
	}
	if wm := watermarkOf(t, ctx, q, tenantC); !wm.Valid || wm.Time.After(past.Add(time.Second)) {
		t.Errorf("tenant C watermark = %v, want unchanged (digest off)", wm.Time)
	}

	// Back-to-back rerun: A's window is now empty (watermark advanced), so nothing
	// new is dispatched.
	enq2 := &fakeEmailEnqueuer{}
	w.Dispatcher = notify.NewDispatcher(notify.NewEmailChannel(enq2))
	n2, err := w.EnqueueDueDigests(ctx)
	if err != nil {
		t.Fatalf("EnqueueDueDigests rerun: %v", err)
	}
	if n2 != 0 {
		t.Errorf("rerun dispatched = %d, want 0 (watermark advanced)", n2)
	}
	if len(enq2.msgs) != 0 {
		t.Errorf("rerun emails = %d, want 0", len(enq2.msgs))
	}
}
