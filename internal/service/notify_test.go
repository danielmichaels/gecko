package service_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgxpool"
)

type uiNotification struct {
	TenantID   int32  `json:"tenant_id"`
	DomainUID  string `json:"domain_uid"`
	EntityType string `json:"entity_type"`
	ChangeType string `json:"change_type"`
}

func awaitDomainNotify(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	mutate func(),
) uiNotification {
	t.Helper()
	listener, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire listener conn: %v", err)
	}
	defer listener.Release()
	if _, err := listener.Exec(ctx, "LISTEN domain_observations"); err != nil {
		t.Fatalf("LISTEN: %v", err)
	}

	mutate()

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	n, err := listener.Conn().WaitForNotification(waitCtx)
	if err != nil {
		t.Fatalf("expected a notification, got: %v", err)
	}
	var got uiNotification
	if err := json.Unmarshal([]byte(n.Payload), &got); err != nil {
		t.Fatalf("payload not JSON: %q: %v", n.Payload, err)
	}
	return got
}

func TestDomainsService_Delete_NotifiesUI(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ds := svc.DomainsService()
	tenant := createTenant(t, ctx, pc, "a@notify-del.com")
	d := seedDomain(t, ctx, pc, tenant, "del.example.com")

	got := awaitDomainNotify(t, ctx, pc.Pool, func() {
		if err := ds.Delete(ctx, ownerPrincipal(tenant), d.Uid); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	})
	if got.TenantID != tenant || got.DomainUID != d.Uid {
		t.Fatalf("notification = %+v, want tenant %d domain %s", got, tenant, d.Uid)
	}
	if got.EntityType != "domain" || got.ChangeType != "deleted" {
		t.Errorf("notification = %+v, want entity 'domain' change 'deleted'", got)
	}
}

func TestDomainsService_Create_NotifiesUI(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ds := svc.DomainsService()
	tenant := createTenant(t, ctx, pc, "a@notify-create.com")

	got := awaitDomainNotify(t, ctx, pc.Pool, func() {
		if _, err := ds.Create(ctx, ownerPrincipal(tenant), service.DomainsCreateParams{
			Domain: "new.example.com",
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	})
	if got.TenantID != tenant {
		t.Fatalf("notification = %+v, want tenant %d", got, tenant)
	}
	if got.EntityType != "domain" || got.ChangeType != "created" {
		t.Errorf("notification = %+v, want entity 'domain' change 'created'", got)
	}
}

func TestDomainsService_Update_NotifiesUI(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ds := svc.DomainsService()
	tenant := createTenant(t, ctx, pc, "a@notify-update.com")
	d := seedDomain(t, ctx, pc, tenant, "upd.example.com")

	got := awaitDomainNotify(t, ctx, pc.Pool, func() {
		if _, err := ds.Update(ctx, ownerPrincipal(tenant), d.Uid, service.DomainsUpdateParams{
			Status: "inactive",
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
	})
	if got.TenantID != tenant || got.DomainUID != d.Uid {
		t.Fatalf("notification = %+v, want tenant %d domain %s", got, tenant, d.Uid)
	}
	if got.EntityType != "domain" || got.ChangeType != "updated" {
		t.Errorf("notification = %+v, want entity 'domain' change 'updated'", got)
	}
}
