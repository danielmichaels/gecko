package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func recordAObservation(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	d store.DomainsInsertRow,
	tenantID int32,
	ips []string,
) {
	t.Helper()
	scan, err := pc.Queries.ScansCreate(ctx, store.ScansCreateParams{
		TenantID:   tenantID,
		DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
		DomainUid:  d.Uid,
		DomainName: d.Name,
		Source:     store.DomainSourceUserSupplied,
	})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	tx, err := pc.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	rec := observer.New(pc.Queries.WithTx(tx))
	if err := rec.RecordA(ctx, observer.DomainIdentity{
		TenantID:   tenantID,
		DomainID:   d.ID,
		DomainUID:  d.Uid,
		DomainName: d.Name,
		ScanID:     scan.ID,
	}, ips, true); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("RecordA: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestRecordsService_List_HappyPath(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	rs := svc.RecordsService()

	tenantA := createTenant(t, ctx, pc, "a@records-list.com")
	d := seedDomain(t, ctx, pc, tenantA, "records.example.com")

	// No records yet — should return empty slices without error.
	result, err := rs.List(ctx, ownerPrincipal(tenantA), d.Uid, nil)
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if result.Records.DomainName != d.Name {
		t.Errorf("domain name = %s, want %s", result.Records.DomainName, d.Name)
	}
}

func TestRecordsService_List_CrossTenantReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	rs := svc.RecordsService()

	tenantA := createTenant(t, ctx, pc, "a@records-cross.com")
	tenantB := createTenant(t, ctx, pc, "b@records-cross.com")
	d := seedDomain(t, ctx, pc, tenantB, "b-records.example.com")

	_, err = rs.List(ctx, ownerPrincipal(tenantA), d.Uid, nil)
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant List = %v, want ErrNotFound", err)
	}
}

func TestRecordsService_List_InvalidQTypeReturnsInvalidInput(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	rs := svc.RecordsService()

	tenantA := createTenant(t, ctx, pc, "a@records-invalid.com")
	d := seedDomain(t, ctx, pc, tenantA, "invalid-qtype.example.com")

	_, err = rs.List(ctx, ownerPrincipal(tenantA), d.Uid, []string{"bogus"})
	if !errors.Is(err, service.ErrInvalidInput) {
		t.Errorf("invalid qtype = %v, want ErrInvalidInput", err)
	}
}

func TestRecordsService_History_HappyPath(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	rs := svc.RecordsService()

	tenantA := createTenant(t, ctx, pc, "a@history-test.com")
	d := seedDomain(t, ctx, pc, tenantA, "history.example.com")
	recordAObservation(t, ctx, pc, d, tenantA, []string{"1.2.3.4"})

	result, err := rs.History(ctx, ownerPrincipal(tenantA), d.Uid, "")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(result.History) != 1 {
		t.Fatalf("history len = %d, want 1", len(result.History))
	}
	if result.History[0].EntityKey != "1.2.3.4" {
		t.Errorf("entity key = %s, want 1.2.3.4", result.History[0].EntityKey)
	}
}

func TestRecordsService_History_CrossTenantReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	rs := svc.RecordsService()

	tenantA := createTenant(t, ctx, pc, "a@hist-cross.com")
	tenantB := createTenant(t, ctx, pc, "b@hist-cross.com")
	d := seedDomain(t, ctx, pc, tenantB, "b-hist.example.com")

	_, err = rs.History(ctx, ownerPrincipal(tenantA), d.Uid, "")
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant History = %v, want ErrNotFound", err)
	}
}

func TestRecordsService_History_InvalidQTypeReturnsInvalidInput(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	rs := svc.RecordsService()

	tenantA := createTenant(t, ctx, pc, "a@hist-invalid.com")
	d := seedDomain(t, ctx, pc, tenantA, "hist-invalid.example.com")

	_, err = rs.History(ctx, ownerPrincipal(tenantA), d.Uid, "bogus")
	if !errors.Is(err, service.ErrInvalidInput) {
		t.Errorf("invalid qtype History = %v, want ErrInvalidInput", err)
	}
}

func TestRecordsService_History_QtypeFilter(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	rs := svc.RecordsService()

	tenantA := createTenant(t, ctx, pc, "a@hist-filter.com")
	d := seedDomain(t, ctx, pc, tenantA, "hist-filter.example.com")
	recordAObservation(t, ctx, pc, d, tenantA, []string{"9.9.9.9"})

	// Filter by cname — should return empty (only A records exist).
	result, err := rs.History(ctx, ownerPrincipal(tenantA), d.Uid, "cname")
	if err != nil {
		t.Fatalf("History cname filter: %v", err)
	}
	if len(result.History) != 0 {
		t.Errorf("cname filter returned %d entries, want 0", len(result.History))
	}

	// Filter by a — should return the observation.
	result, err = rs.History(ctx, ownerPrincipal(tenantA), d.Uid, "a")
	if err != nil {
		t.Fatalf("History a filter: %v", err)
	}
	if len(result.History) != 1 {
		t.Errorf("a filter returned %d entries, want 1", len(result.History))
	}
}

func TestRecordsService_Timeline_HappyPath(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	rs := svc.RecordsService()

	tenantA := createTenant(t, ctx, pc, "a@timeline-test.com")
	d := seedDomain(t, ctx, pc, tenantA, "timeline.example.com")
	recordAObservation(t, ctx, pc, d, tenantA, []string{"1.1.1.1"})
	recordAObservation(t, ctx, pc, d, tenantA, []string{"1.1.1.1", "2.2.2.2"})

	result, err := rs.Timeline(ctx, ownerPrincipal(tenantA), d.Uid)
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	if len(result.Scans) != 2 {
		t.Errorf("timeline scans = %d, want 2", len(result.Scans))
	}
}

func TestRecordsService_Timeline_CrossTenantReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	rs := svc.RecordsService()

	tenantA := createTenant(t, ctx, pc, "a@tl-cross.com")
	tenantB := createTenant(t, ctx, pc, "b@tl-cross.com")
	d := seedDomain(t, ctx, pc, tenantB, "b-tl.example.com")

	_, err = rs.Timeline(ctx, ownerPrincipal(tenantA), d.Uid)
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant Timeline = %v, want ErrNotFound", err)
	}
}
