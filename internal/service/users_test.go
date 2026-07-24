package service_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

func setupTenantWithUsers(
	t *testing.T,
	pc *testhelpers.TestDatabase,
) (authSvc *service.AuthService, usersSvc *service.UsersService) {
	t.Helper()
	cfg := config.AppConfig()
	cfg.Auth.BcryptCost = 4

	provider, err := auth.NewProvider(auth.Config{Provider: "local", BcryptCost: 4}, pc.Queries)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	svc := service.NewWithScheduler(
		cfg,
		slog.New(slog.DiscardHandler),
		pc.Queries,
		pc.Pool,
		nil,
		provider,
	)
	return svc.AuthService(), svc.UsersService()
}

func principalForEmail(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.TestDatabase,
	email string,
) *auth.Principal {
	t.Helper()
	return testhelpers.PrincipalForEmail(t, ctx, pc, email)
}

func inviteMember(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.TestDatabase,
	authSvc *service.AuthService,
	inviterP *auth.Principal,
	email, role string,
) {
	t.Helper()
	rawToken := seedInvitation(t, ctx, pc, inviterP.TenantID, email,
		store.UserRole(role), pgtype.Int4{Int32: inviterP.UserID, Valid: true})
	_, err := authSvc.AcceptInvite(ctx, service.AcceptInviteParams{
		Token:    rawToken,
		Password: "supersecret",
	})
	if err != nil {
		t.Fatalf("accept invite for %s: %v", email, err)
	}
}

func TestUsersService_List_TenantScoped(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)

	signupUser(t, authSvc, "owner@a.com", "supersecret")
	signupUser(t, authSvc, "owner@b.com", "supersecret")

	pA := principalForEmail(t, ctx, pc, "owner@a.com")
	pB := principalForEmail(t, ctx, pc, "owner@b.com")

	listA, err := usersSvc.List(ctx, pA)
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	listB, err := usersSvc.List(ctx, pB)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}

	if len(listA) != 1 || listA[0].Email != "owner@a.com" {
		t.Errorf("tenant A list = %v, want only owner@a.com", listA)
	}
	if len(listB) != 1 || listB[0].Email != "owner@b.com" {
		t.Errorf("tenant B list = %v, want only owner@b.com", listB)
	}
}

func TestUsersService_Update_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	inviteMember(t, ctx, pc, authSvc, pOwner, "viewer@a.com", "viewer")
	vUser, err := pc.Queries.UserGetByEmail(ctx, "viewer@a.com")
	if err != nil {
		t.Fatalf("viewer lookup: %v", err)
	}

	updated, err := usersSvc.Update(ctx, pOwner, vUser.Uid, service.UsersUpdateParams{
		Role: "manager",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Role != "manager" {
		t.Errorf("role = %q, want %q", updated.Role, "manager")
	}
	if updated.Email != "viewer@a.com" {
		t.Errorf("email = %q, want unchanged %q", updated.Email, "viewer@a.com")
	}
}

func TestUsersService_Update_ViewerForbidden(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	inviteMember(t, ctx, pc, authSvc, pOwner, "viewer@a.com", "viewer")
	pViewer := principalForEmail(t, ctx, pc, "viewer@a.com")

	oUser, err := pc.Queries.UserGetByEmail(ctx, "owner@a.com")
	if err != nil {
		t.Fatalf("owner user lookup: %v", err)
	}

	_, err = usersSvc.Update(ctx, pViewer, oUser.Uid, service.UsersUpdateParams{
		Role: "viewer",
	})
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("viewer update: want ErrForbidden, got %v", err)
	}
	if err.Error() != "insufficient permissions" {
		t.Errorf("viewer update message = %q, want %q", err.Error(), "insufficient permissions")
	}
}

func TestUsersService_Update_ManagerCannotGrantOwner(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	inviteMember(t, ctx, pc, authSvc, pOwner, "mgr@a.com", "manager")
	inviteMember(t, ctx, pc, authSvc, pOwner, "viewer@a.com", "viewer")
	pMgr := principalForEmail(t, ctx, pc, "mgr@a.com")
	vUser, err := pc.Queries.UserGetByEmail(ctx, "viewer@a.com")
	if err != nil {
		t.Fatalf("viewer lookup: %v", err)
	}

	_, err = usersSvc.Update(ctx, pMgr, vUser.Uid, service.UsersUpdateParams{
		Role: "owner",
	})
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager grant owner: want ErrForbidden, got %v", err)
	}
	if err.Error() != "cannot grant a role above your own" {
		t.Errorf("message = %q, want %q", err.Error(), "cannot grant a role above your own")
	}
}

func TestUsersService_Update_ManagerCannotModifyOwner(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	inviteMember(t, ctx, pc, authSvc, pOwner, "mgr@a.com", "manager")
	pMgr := principalForEmail(t, ctx, pc, "mgr@a.com")
	oUser, err := pc.Queries.UserGetByEmail(ctx, "owner@a.com")
	if err != nil {
		t.Fatalf("owner lookup: %v", err)
	}

	_, err = usersSvc.Update(ctx, pMgr, oUser.Uid, service.UsersUpdateParams{
		Role: "viewer",
	})
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager modify owner: want ErrForbidden, got %v", err)
	}
	if err.Error() != "cannot modify a user above your own role" {
		t.Errorf("message = %q, want %q", err.Error(), "cannot modify a user above your own role")
	}
}

func TestUsersService_Update_CrossTenant(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	signupUser(t, authSvc, "owner@b.com", "supersecret")
	pA := principalForEmail(t, ctx, pc, "owner@a.com")
	bUser, err := pc.Queries.UserGetByEmail(ctx, "owner@b.com")
	if err != nil {
		t.Fatalf("b user lookup: %v", err)
	}

	_, err = usersSvc.Update(ctx, pA, bUser.Uid, service.UsersUpdateParams{
		Role: "viewer",
	})
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant update: want ErrNotFound, got %v", err)
	}
	if err.Error() != "user not found" {
		t.Errorf("message = %q, want %q", err.Error(), "user not found")
	}
}

func TestUsersService_Update_LastOwnerDemote(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")
	oUser, err := pc.Queries.UserGetByEmail(ctx, "owner@a.com")
	if err != nil {
		t.Fatalf("owner lookup: %v", err)
	}

	_, err = usersSvc.Update(ctx, pOwner, oUser.Uid, service.UsersUpdateParams{
		Role: "manager",
	})
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("last-owner demote: want ErrConflict, got %v", err)
	}
	if err.Error() != "cannot remove the last owner of a tenant" {
		t.Errorf("message = %q, want %q", err.Error(), "cannot remove the last owner of a tenant")
	}
}

func TestUsersService_Delete_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	inviteMember(t, ctx, pc, authSvc, pOwner, "viewer@a.com", "viewer")
	vUser, err := pc.Queries.UserGetByEmail(ctx, "viewer@a.com")
	if err != nil {
		t.Fatalf("viewer lookup: %v", err)
	}

	if err := usersSvc.Delete(ctx, pOwner, vUser.Uid); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestUsersService_Delete_ViewerForbidden(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	inviteMember(t, ctx, pc, authSvc, pOwner, "viewer@a.com", "viewer")
	pViewer := principalForEmail(t, ctx, pc, "viewer@a.com")
	oUser, err := pc.Queries.UserGetByEmail(ctx, "owner@a.com")
	if err != nil {
		t.Fatalf("owner lookup: %v", err)
	}

	err = usersSvc.Delete(ctx, pViewer, oUser.Uid)
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("viewer delete: want ErrForbidden, got %v", err)
	}
	if err.Error() != "insufficient permissions" {
		t.Errorf("message = %q, want %q", err.Error(), "insufficient permissions")
	}
}

func TestUsersService_Delete_ManagerCannotDeleteOwner(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	inviteMember(t, ctx, pc, authSvc, pOwner, "mgr@a.com", "manager")
	pMgr := principalForEmail(t, ctx, pc, "mgr@a.com")
	oUser, err := pc.Queries.UserGetByEmail(ctx, "owner@a.com")
	if err != nil {
		t.Fatalf("owner lookup: %v", err)
	}

	err = usersSvc.Delete(ctx, pMgr, oUser.Uid)
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager delete owner: want ErrForbidden, got %v", err)
	}
	if err.Error() != "cannot modify a user above your own role" {
		t.Errorf("message = %q, want %q", err.Error(), "cannot modify a user above your own role")
	}
}

func TestUsersService_Delete_CrossTenant(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	signupUser(t, authSvc, "owner@b.com", "supersecret")
	pA := principalForEmail(t, ctx, pc, "owner@a.com")
	bUser, err := pc.Queries.UserGetByEmail(ctx, "owner@b.com")
	if err != nil {
		t.Fatalf("b user lookup: %v", err)
	}

	err = usersSvc.Delete(ctx, pA, bUser.Uid)
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant delete: want ErrNotFound, got %v", err)
	}
	if err.Error() != "user not found" {
		t.Errorf("message = %q, want %q", err.Error(), "user not found")
	}
}

func TestUsersService_Delete_LastOwner(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")
	oUser, err := pc.Queries.UserGetByEmail(ctx, "owner@a.com")
	if err != nil {
		t.Fatalf("owner lookup: %v", err)
	}

	err = usersSvc.Delete(ctx, pOwner, oUser.Uid)
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("last-owner delete: want ErrConflict, got %v", err)
	}
	if err.Error() != "cannot remove the last owner of a tenant" {
		t.Errorf("message = %q, want %q", err.Error(), "cannot remove the last owner of a tenant")
	}
}

func TestUsersService_ManagerSelfPromote(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, usersSvc := setupTenantWithUsers(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	inviteMember(t, ctx, pc, authSvc, pOwner, "mgr@a.com", "manager")
	pMgr := principalForEmail(t, ctx, pc, "mgr@a.com")
	mgrUser, err := pc.Queries.UserGetByEmail(ctx, "mgr@a.com")
	if err != nil {
		t.Fatalf("mgr lookup: %v", err)
	}

	_, err = usersSvc.Update(ctx, pMgr, mgrUser.Uid, service.UsersUpdateParams{
		Role: "owner",
	})
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager self-promote: want ErrForbidden, got %v", err)
	}
	if err.Error() != "cannot grant a role above your own" {
		t.Errorf("message = %q, want %q", err.Error(), "cannot grant a role above your own")
	}
}

func TestMessagedError_Unwrap(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	err := service.MsgErrExported(service.ErrForbidden, "custom message")
	if !errors.Is(err, service.ErrForbidden) {
		t.Error("errors.Is(msgErr(ErrForbidden, ...), ErrForbidden) must be true")
	}
	if err.Error() != "custom message" {
		t.Errorf("Error() = %q, want %q", err.Error(), "custom message")
	}
	if errors.Is(err, service.ErrNotFound) {
		t.Error("errors.Is(msgErr(ErrForbidden, ...), ErrNotFound) must be false")
	}
}
