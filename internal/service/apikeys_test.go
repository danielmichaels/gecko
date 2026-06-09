package service_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

func setupAPIKeysService(
	t *testing.T,
	pc *testhelpers.PostgresContainer,
) (authSvc *service.AuthService, keysSvc *service.APIKeysService) {
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
	return svc.AuthService(), svc.APIKeysService()
}

// TestAPIKeysService_Create_HappyPath verifies owner can create an API key.
func TestAPIKeysService_Create_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, keysSvc := setupAPIKeysService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	result, err := keysSvc.Create(ctx, pOwner, "my-key")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if result.UID == "" {
		t.Error("uid should not be empty")
	}
	if result.Raw == "" {
		t.Error("raw key should not be empty")
	}
	if result.Prefix == "" {
		t.Error("prefix should not be empty")
	}
}

// TestAPIKeysService_Create_ViewerForbidden verifies viewer cannot create API keys.
func TestAPIKeysService_Create_ViewerForbidden(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, keysSvc := setupAPIKeysService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")
	inviteMember(t, ctx, pc, authSvc, pOwner, "viewer@a.com", "viewer")
	pViewer := principalForEmail(t, ctx, pc, "viewer@a.com")

	_, err = keysSvc.Create(ctx, pViewer, "viewer-key")
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("viewer create key: want ErrForbidden, got %v", err)
	}
	if err.Error() != "insufficient permissions" {
		t.Errorf("message = %q, want %q", err.Error(), "insufficient permissions")
	}
}

// TestAPIKeysService_Create_ManagerAllowed verifies manager can create API keys.
func TestAPIKeysService_Create_ManagerAllowed(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, keysSvc := setupAPIKeysService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")
	inviteMember(t, ctx, pc, authSvc, pOwner, "mgr@a.com", "manager")
	pMgr := principalForEmail(t, ctx, pc, "mgr@a.com")

	result, err := keysSvc.Create(ctx, pMgr, "mgr-key")
	if err != nil {
		t.Fatalf("manager create key: %v", err)
	}
	if result.UID == "" {
		t.Error("uid should not be empty")
	}
}

// TestAPIKeysService_List_TenantScoped verifies List returns only the caller's tenant keys.
func TestAPIKeysService_List_TenantScoped(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, keysSvc := setupAPIKeysService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	signupUser(t, authSvc, "owner@b.com", "supersecret")
	pA := principalForEmail(t, ctx, pc, "owner@a.com")
	pB := principalForEmail(t, ctx, pc, "owner@b.com")

	_, err = keysSvc.Create(ctx, pA, "key-a")
	if err != nil {
		t.Fatalf("create key for A: %v", err)
	}

	rowsA, err := keysSvc.List(ctx, pA)
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	rowsB, err := keysSvc.List(ctx, pB)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}

	// Tenant A should have signup key + created key; B should have only its signup key.
	foundA := false
	for _, r := range rowsA {
		if r.Name == "key-a" {
			foundA = true
		}
	}
	if !foundA {
		t.Error("tenant A list should contain 'key-a'")
	}
	for _, r := range rowsB {
		if r.Name == "key-a" {
			t.Error("tenant B should not see tenant A's key")
		}
	}
}

// TestAPIKeysService_Revoke_HappyPath verifies owner can revoke an API key.
func TestAPIKeysService_Revoke_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, keysSvc := setupAPIKeysService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	result, err := keysSvc.Create(ctx, pOwner, "to-revoke")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	if err := keysSvc.Revoke(ctx, pOwner, result.UID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

// TestAPIKeysService_Revoke_ViewerForbidden verifies viewer cannot revoke API keys.
func TestAPIKeysService_Revoke_ViewerForbidden(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, keysSvc := setupAPIKeysService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")
	inviteMember(t, ctx, pc, authSvc, pOwner, "viewer@a.com", "viewer")
	pViewer := principalForEmail(t, ctx, pc, "viewer@a.com")

	err = keysSvc.Revoke(ctx, pViewer, "apikey_00000001")
	if !errors.Is(err, service.ErrForbidden) {
		t.Errorf("viewer revoke: want ErrForbidden, got %v", err)
	}
	if err.Error() != "insufficient permissions" {
		t.Errorf("message = %q, want %q", err.Error(), "insufficient permissions")
	}
}

// TestAPIKeysService_Revoke_CrossTenant verifies cross-tenant revoke returns ErrNotFound.
func TestAPIKeysService_Revoke_CrossTenant(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, keysSvc := setupAPIKeysService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	signupUser(t, authSvc, "owner@b.com", "supersecret")
	pA := principalForEmail(t, ctx, pc, "owner@a.com")
	pB := principalForEmail(t, ctx, pc, "owner@b.com")

	// Create key in tenant A.
	resultA, err := keysSvc.Create(ctx, pA, "key-a")
	if err != nil {
		t.Fatalf("create key for A: %v", err)
	}

	// Tenant B owner tries to revoke tenant A's key.
	err = keysSvc.Revoke(ctx, pB, resultA.UID)
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("cross-tenant revoke: want ErrNotFound, got %v", err)
	}
	if err.Error() != "api key not found" {
		t.Errorf("message = %q, want %q", err.Error(), "api key not found")
	}
}

// TestAPIKeysService_Revoke_NotFound verifies revoking non-existent key returns ErrNotFound.
func TestAPIKeysService_Revoke_NotFound(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, keysSvc := setupAPIKeysService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	err = keysSvc.Revoke(ctx, pOwner, "apikey_doesnotexist")
	if !errors.Is(err, service.ErrNotFound) {
		t.Errorf("not found: want ErrNotFound, got %v", err)
	}
	if err.Error() != "api key not found" {
		t.Errorf("message = %q, want %q", err.Error(), "api key not found")
	}
}

// TestAPIKeysService_Create_KeyIsUsable verifies the returned raw key authenticates.
func TestAPIKeysService_Create_KeyIsUsable(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	authSvc, keysSvc := setupAPIKeysService(t, pc)
	signupUser(t, authSvc, "owner@a.com", "supersecret")
	pOwner := principalForEmail(t, ctx, pc, "owner@a.com")

	result, err := keysSvc.Create(ctx, pOwner, "usable-key")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	// The raw key should be verifiable against the DB.
	p, _, err := auth.VerifyAPIKey(ctx, pc.Queries, result.Raw)
	if err != nil {
		t.Fatalf("verify key: %v", err)
	}
	if p.TenantID != pOwner.TenantID {
		t.Errorf("tenant mismatch: got %d, want %d", p.TenantID, pOwner.TenantID)
	}
	if p.UserID != pOwner.UserID {
		t.Errorf("user mismatch: got %d, want %d", p.UserID, pOwner.UserID)
	}
}
