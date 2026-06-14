package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

func TestNotificationsService_GetDefaultsWhenNoRow(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ns := svc.NotificationsService()
	tenant := createTenant(t, ctx, pc, "a@notif-default.com")

	got, err := ns.GetNotificationSettings(ctx, ownerPrincipal(tenant))
	if err != nil {
		t.Fatalf("GetNotificationSettings: %v", err)
	}
	if !got.DailyDigest || !got.HighImpact {
		t.Errorf("defaults = %+v, want both true (opt-out)", got)
	}
}

func TestNotificationsService_SetAndGet(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ns := svc.NotificationsService()
	tenant := createTenant(t, ctx, pc, "a@notif-set.com")

	if err := ns.SetNotificationSettings(ctx, ownerPrincipal(tenant), service.NotificationSettings{
		DailyDigest: false,
		HighImpact:  true,
	}); err != nil {
		t.Fatalf("SetNotificationSettings: %v", err)
	}

	got, err := ns.GetNotificationSettings(ctx, ownerPrincipal(tenant))
	if err != nil {
		t.Fatalf("GetNotificationSettings: %v", err)
	}
	if got.DailyDigest {
		t.Errorf("DailyDigest = true, want false after set")
	}
	if !got.HighImpact {
		t.Errorf("HighImpact = false, want true after set")
	}
}

func TestNotificationsService_SetRequiresOwnerOrManager(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newTestService(pc, &fakeScheduler{})
	ns := svc.NotificationsService()
	tenant := createTenant(t, ctx, pc, "a@notif-perm.com")

	err = ns.SetNotificationSettings(
		ctx,
		principalWithRole(tenant, "viewer"),
		service.NotificationSettings{
			DailyDigest: false,
			HighImpact:  false,
		},
	)
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("viewer Set err = %v, want ErrForbidden", err)
	}

	// A manager is allowed.
	if err := ns.SetNotificationSettings(ctx, principalWithRole(tenant, "manager"), service.NotificationSettings{
		DailyDigest: true,
		HighImpact:  false,
	}); err != nil {
		t.Fatalf("manager Set err = %v, want nil", err)
	}
}
