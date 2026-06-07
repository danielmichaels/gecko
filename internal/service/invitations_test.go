package service_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

func setupInvitationsService(
	t *testing.T,
	pc *testhelpers.PostgresContainer,
) (authSvc *service.AuthService, invSvc *service.InvitationsService) {
	t.Helper()
	cfg := config.AppConfig()
	cfg.Auth.BcryptCost = 4
	cfg.Auth.InviteTTL = 24 * time.Hour

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
	return svc.AuthService(), svc.InvitationsService()
}

// TestInvitationsService_Create_HappyPath verifies owner can create an invitation.
func TestInvitationsService_Create_HappyPath(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, invSvc := setupInvitationsService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	result, err := invSvc.Create(ctx, pOwner, service.InvitationsCreateParams{
		Email: "newuser@a.com",
		Role:  "viewer",
	})
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}
	if result.Token == "" {
		t.Error("token should not be empty")
	}
	if result.Email != "newuser@a.com" {
		t.Errorf("email = %q, want %q", result.Email, "newuser@a.com")
	}
	if result.Role != "viewer" {
		t.Errorf("role = %q, want %q", result.Role, "viewer")
	}
	if result.ExpiresAt.IsZero() {
		t.Error("expires_at should not be zero")
	}
}

// TestInvitationsService_Create_ViewerForbidden verifies viewer cannot create invitation.
func TestInvitationsService_Create_ViewerForbidden(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, invSvc := setupInvitationsService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")
	inviteMember(t, ctx, pc, authSvc, pOwner, "viewer@a.com", "viewer")
	pViewer := principalForEmail(t, ctx, pc, "viewer@a.com")

	_, err = invSvc.Create(ctx, pViewer, service.InvitationsCreateParams{
		Email: "other@a.com",
		Role:  "viewer",
	})
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("viewer create: want ErrForbidden, got %v", err)
	}
	if err.Error() != "insufficient permissions" {
		t.Errorf("message = %q, want %q", err.Error(), "insufficient permissions")
	}
}

// TestInvitationsService_Create_ManagerCannotGrantOwner verifies manager cannot invite at owner role.
func TestInvitationsService_Create_ManagerCannotGrantOwner(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, invSvc := setupInvitationsService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")
	inviteMember(t, ctx, pc, authSvc, pOwner, "mgr@a.com", "manager")
	pMgr := principalForEmail(t, ctx, pc, "mgr@a.com")

	_, err = invSvc.Create(ctx, pMgr, service.InvitationsCreateParams{
		Email: "newowner@a.com",
		Role:  "owner",
	})
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("manager grant owner: want ErrForbidden, got %v", err)
	}
	if err.Error() != "cannot grant a role above your own" {
		t.Errorf("message = %q, want %q", err.Error(), "cannot grant a role above your own")
	}
}

// TestInvitationsService_Create_ExistingUserConflict verifies already-registered email is rejected.
func TestInvitationsService_Create_ExistingUserConflict(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, invSvc := setupInvitationsService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	signupUser(t, authSvc, "existing@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	_, err = invSvc.Create(ctx, pOwner, service.InvitationsCreateParams{
		Email: "existing@a.com",
		Role:  "viewer",
	})
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("existing user: want ErrConflict, got %v", err)
	}
	if err.Error() != "email already registered" {
		t.Errorf("message = %q, want %q", err.Error(), "email already registered")
	}
}

// TestInvitationsService_Create_DuplicatePendingInvite verifies collision on active invite.
func TestInvitationsService_Create_DuplicatePendingInvite(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, invSvc := setupInvitationsService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	// First invite goes through.
	_, err = invSvc.Create(ctx, pOwner, service.InvitationsCreateParams{
		Email: "new@a.com",
		Role:  "viewer",
	})
	if err != nil {
		t.Fatalf("first invite: %v", err)
	}

	// Second invite for same email while first is still live → conflict.
	_, err = invSvc.Create(ctx, pOwner, service.InvitationsCreateParams{
		Email: "new@a.com",
		Role:  "viewer",
	})
	if !errors.Is(err, service.ErrConflict) {
		t.Errorf("duplicate pending invite: want ErrConflict, got %v", err)
	}
	if err.Error() != "an invitation for this email is already pending" {
		t.Errorf(
			"message = %q, want %q",
			err.Error(),
			"an invitation for this email is already pending",
		)
	}
}

// TestInvitationsService_List_TenantScoped verifies List returns only the caller's tenant.
func TestInvitationsService_List_TenantScoped(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, invSvc := setupInvitationsService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	signupUser(t, authSvc, "owner@b.com", "supersecret")
	pA := principalForEmail(t, ctx, pc, "owner@a.com")
	pB := principalForEmail(t, ctx, pc, "owner@b.com")

	_, err = invSvc.Create(
		ctx,
		pA,
		service.InvitationsCreateParams{Email: "inv@a.com", Role: "viewer"},
	)
	if err != nil {
		t.Fatalf("create invite for A: %v", err)
	}

	rowsA, err := invSvc.List(ctx, pA)
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	rowsB, err := invSvc.List(ctx, pB)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}

	if len(rowsA) != 1 {
		t.Errorf("tenant A invitations = %d, want 1", len(rowsA))
	}
	if len(rowsB) != 0 {
		t.Errorf("tenant B invitations = %d, want 0", len(rowsB))
	}
}

// TestInvitationsService_Revoke_HappyPath verifies owner can revoke a pending invite.
func TestInvitationsService_Revoke_HappyPath(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, invSvc := setupInvitationsService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	_, err = invSvc.Create(
		ctx,
		pOwner,
		service.InvitationsCreateParams{Email: "inv@a.com", Role: "viewer"},
	)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	rows, err := invSvc.List(ctx, pOwner)
	if err != nil || len(rows) == 0 {
		t.Fatalf("list before revoke: %v (rows=%d)", err, len(rows))
	}

	if err := invSvc.Revoke(ctx, pOwner, rows[0].Uid); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

// TestInvitationsService_Revoke_ViewerForbidden verifies viewer cannot revoke.
func TestInvitationsService_Revoke_ViewerForbidden(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, invSvc := setupInvitationsService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")
	inviteMember(t, ctx, pc, authSvc, pOwner, "viewer@a.com", "viewer")
	pViewer := principalForEmail(t, ctx, pc, "viewer@a.com")

	err = invSvc.Revoke(ctx, pViewer, "invite_00000001")
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("viewer revoke: want ErrForbidden, got %v", err)
	}
	if err.Error() != "insufficient permissions" {
		t.Errorf("message = %q, want %q", err.Error(), "insufficient permissions")
	}
}

// TestInvitationsService_Revoke_CrossTenant verifies cross-tenant revoke returns ErrNotFound.
func TestInvitationsService_Revoke_CrossTenant(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, invSvc := setupInvitationsService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	signupUser(t, authSvc, "owner@b.com", "supersecret")
	pA := principalForEmail(t, ctx, pc, "owner@a.com")
	pB := principalForEmail(t, ctx, pc, "owner@b.com")

	// Seed an invite in tenant A directly.
	rawToken, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	inv, err := pc.Queries.InvitationCreate(ctx, store.InvitationCreateParams{
		TenantID:  pA.TenantID,
		Email:     "inv@a.com",
		Role:      store.UserRoleViewer,
		TokenHash: auth.HashToken(rawToken),
		InvitedBy: pgtype.Int4{Int32: pA.UserID, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatalf("seed invite: %v", err)
	}

	// Tenant B owner tries to revoke tenant A's invite.
	err = invSvc.Revoke(ctx, pB, inv.Uid)
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant revoke: want ErrNotFound, got %v", err)
	}
	if err.Error() != "invitation not found" {
		t.Errorf("message = %q, want %q", err.Error(), "invitation not found")
	}
}

// TestInvitationsService_TokenUsable verifies the returned token is accepted by AcceptInvite.
func TestInvitationsService_TokenUsable(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, invSvc := setupInvitationsService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	result, err := invSvc.Create(ctx, pOwner, service.InvitationsCreateParams{
		Email: "newuser@a.com",
		Role:  "viewer",
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	// Accept the invitation using the returned token.
	_, err = authSvc.AcceptInvite(ctx, service.AcceptInviteParams{
		Token:    result.Token,
		Password: "supersecret",
		Name:     "New User",
	})
	if err != nil {
		t.Fatalf("accept invite with service token: %v", err)
	}
}
