package jobs

import (
	"context"
	"strings"
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

type fakeEmailEnqueuer struct {
	msgs []mailer.Message
}

func (f *fakeEmailEnqueuer) EnqueueEmail(_ context.Context, _ pgx.Tx, msg mailer.Message) error {
	f.msgs = append(f.msgs, msg)
	return nil
}

func digestTestWorker(
	q *store.Queries,
	pc *testhelpers.TestDatabase,
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
	u, err := q.UserProvisionIdentity(ctx, store.UserProvisionIdentityParams{Email: email})
	if err != nil {
		t.Fatalf("provision user %s: %v", email, err)
	}
	if _, err := q.MembershipCreate(ctx, store.MembershipCreateParams{
		UserID:   u.ID,
		TenantID: tenantID,
		Role:     role,
	}); err != nil {
		t.Fatalf("create membership %s: %v", email, err)
	}
}

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

func seedObservation(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.TestDatabase,
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

func TestDailyDigestWorker_EnqueueDueDigests(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)
	q := pc.Queries

	past := time.Now().Add(-1 * time.Hour)

	tenantA := seedStatsTenant(t, ctx, q, "owner@a.digest.test")
	enableDigest(t, ctx, q, tenantA, true, past)
	domA := seedStatsDomain(t, ctx, q, tenantA, "a.digest.test")
	seedRecipient(t, ctx, q, tenantA, "owner@a.digest.test", store.UserRoleOwner)
	seedRecipient(t, ctx, q, tenantA, "mgr@a.digest.test", store.UserRoleManager)
	seedRecipient(t, ctx, q, tenantA, "viewer@a.digest.test", store.UserRoleViewer)
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

	tenantB := seedStatsTenant(t, ctx, q, "owner@b.digest.test")
	enableDigest(t, ctx, q, tenantB, true, past)
	seedRecipient(t, ctx, q, tenantB, "owner@b.digest.test", store.UserRoleOwner)

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

	if wm := watermarkOf(t, ctx, q, tenantA); !wm.Valid || !wm.Time.After(past) {
		t.Errorf("tenant A watermark = %v, want advanced past %v", wm.Time, past)
	}
	if wm := watermarkOf(t, ctx, q, tenantB); !wm.Valid || !wm.Time.After(past) {
		t.Errorf("tenant B watermark = %v, want advanced (empty window still advances)", wm.Time)
	}
	if wm := watermarkOf(t, ctx, q, tenantC); !wm.Valid || wm.Time.After(past.Add(time.Second)) {
		t.Errorf("tenant C watermark = %v, want unchanged (digest off)", wm.Time)
	}

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

func TestDailyDigestWorker_HighImpactToggleOff(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)
	q := pc.Queries

	past := time.Now().Add(-1 * time.Hour)

	tenant := seedStatsTenant(t, ctx, q, "owner@hi.digest.test")
	if _, err := q.NotificationSettingsUpsert(ctx, store.NotificationSettingsUpsertParams{
		TenantID:          tenant,
		NotifyDailyDigest: true,
		NotifyHighImpact:  false,
	}); err != nil {
		t.Fatalf("upsert settings: %v", err)
	}
	if err := q.NotificationDigestAdvanceWatermark(ctx, store.NotificationDigestAdvanceWatermarkParams{
		SentAt:   pgtype.Timestamptz{Time: past, Valid: true},
		TenantID: tenant,
	}); err != nil {
		t.Fatalf("set watermark: %v", err)
	}
	dom := seedStatsDomain(t, ctx, q, tenant, "hi.digest.test")
	seedRecipient(t, ctx, q, tenant, "owner@hi.digest.test", store.UserRoleOwner)
	seedObservation(t, ctx, pc, tenant, dom, "hi.digest.test",
		"dangling_cname_finding", "created", `{"severity":"critical","status":"open"}`)

	enq := &fakeEmailEnqueuer{}
	w := digestTestWorker(q, pc, enq)

	if _, err := w.EnqueueDueDigests(ctx); err != nil {
		t.Fatalf("EnqueueDueDigests: %v", err)
	}
	if len(enq.msgs) != 1 {
		t.Fatalf("emails = %d, want 1 (digest still sent)", len(enq.msgs))
	}
	m := enq.msgs[0]
	if strings.Contains(m.Subject, "high-impact") {
		t.Errorf("subject mentions high-impact with toggle off: %q", m.Subject)
	}
	if strings.Contains(m.HTML, "high-impact") || strings.Contains(m.Text, "high-impact") {
		t.Errorf("body includes high-impact section with toggle off:\nHTML=%s", m.HTML)
	}
}
