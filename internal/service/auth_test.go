package service_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

// newAuthSvc builds a real AuthService backed by a test container.
func newAuthSvc(t *testing.T, pc *testhelpers.PostgresContainer) *service.AuthService {
	t.Helper()
	cfg := config.AppConfig()
	cfg.Auth.BcryptCost = 4
	cfg.Auth.SessionTTL = 720 * time.Hour

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
	return svc.AuthService()
}

// TestAuthService_ChangePassword_HappyPath verifies a correct current password
// lets the user set a new one, after which the new password authenticates and
// the old one no longer does.
func TestAuthService_ChangePassword_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "user@a.com", "oldpassword")
	p := principalForEmail(t, ctx, pc, "user@a.com")

	if err := svc.ChangePassword(ctx, p, "oldpassword", "newpassword"); err != nil {
		t.Fatalf("change password: %v", err)
	}

	if _, err := svc.Authenticate(ctx, "user@a.com", "newpassword"); err != nil {
		t.Errorf("authenticate with new password: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "user@a.com", "oldpassword"); !errors.Is(
		err,
		service.ErrUnauthenticated,
	) {
		t.Errorf("old password should be rejected: got %v", err)
	}
}

// TestAuthService_ChangePassword_WrongCurrent verifies an incorrect current
// password is rejected as invalid input and leaves the password unchanged.
func TestAuthService_ChangePassword_WrongCurrent(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "user@a.com", "oldpassword")
	p := principalForEmail(t, ctx, pc, "user@a.com")

	err = svc.ChangePassword(ctx, p, "wrongcurrent", "newpassword")
	if !errors.Is(err, service.ErrInvalidInput) {
		t.Fatalf("wrong current: want ErrInvalidInput, got %v", err)
	}
	if err.Error() != "current password is incorrect" {
		t.Errorf("message = %q, want %q", err.Error(), "current password is incorrect")
	}

	if _, err := svc.Authenticate(ctx, "user@a.com", "oldpassword"); err != nil {
		t.Errorf("original password should still work: %v", err)
	}
}

// TestAuthService_ChangePassword_WeakNew verifies a too-short new password is
// rejected as invalid input.
func TestAuthService_ChangePassword_WeakNew(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "user@a.com", "oldpassword")
	p := principalForEmail(t, ctx, pc, "user@a.com")

	err = svc.ChangePassword(ctx, p, "oldpassword", "short")
	if !errors.Is(err, service.ErrInvalidInput) {
		t.Fatalf("weak new: want ErrInvalidInput, got %v", err)
	}
	if err.Error() != "new password must be at least 8 characters" {
		t.Errorf("message = %q, want %q", err.Error(), "new password must be at least 8 characters")
	}
}

// signupUser is a test helper that creates a user via Signup and returns the result.
func signupUser(
	t *testing.T,
	svc *service.AuthService,
	email, password string,
) service.SignupResult {
	t.Helper()
	result, err := svc.Signup(context.Background(), service.SignupParams{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("signup %s: %v", email, err)
	}
	return result
}

// tenantOf returns u's default-membership tenant id (tenant lives on memberships).
func tenantOf(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	u store.Users,
) int32 {
	t.Helper()
	return testhelpers.PrincipalForEmail(t, ctx, pc, u.Email).TenantID
}

// roleOf returns u's default-membership role (role lives on memberships).
func roleOf(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	u store.Users,
) string {
	t.Helper()
	return testhelpers.PrincipalForEmail(t, ctx, pc, u.Email).Role
}

// seedInvitation inserts a live invitation directly into the DB for AcceptInvite tests.
func seedInvitation(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	tenantID int32,
	email string,
	role store.UserRole,
	invitedBy pgtype.Int4,
) string {
	t.Helper()
	rawToken, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("generate invite token: %v", err)
	}
	_, err = pc.Queries.InvitationCreate(ctx, store.InvitationCreateParams{
		TenantID:  tenantID,
		Email:     email,
		Role:      role,
		TokenHash: auth.HashToken(rawToken),
		InvitedBy: invitedBy,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	})
	if err != nil {
		t.Fatalf("seed invitation for %s: %v", email, err)
	}
	return rawToken
}

func TestAuthService_Login_Valid(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signup := signupUser(t, svc, "user@example.com", "password123")

	result, err := svc.Login(ctx, "user@example.com", "password123")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.RawKey == "" {
		t.Error("login: raw key is empty")
	}
	if result.Email != "user@example.com" {
		t.Errorf("login email = %q, want %q", result.Email, "user@example.com")
	}
	if result.Role != string(store.UserRoleOwner) {
		t.Errorf("login role = %q, want %q", result.Role, string(store.UserRoleOwner))
	}
	// Login should mint a fresh key, not the same as signup's.
	if result.RawKey == signup.RawKey {
		t.Error("login should mint a fresh key distinct from the signup key")
	}
}

func TestAuthService_Login_Invalid(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "user@example.com", "password123")

	_, err = svc.Login(ctx, "user@example.com", "wrongpassword")
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if !isErr(err, service.ErrUnauthenticated) {
		t.Errorf("wrong password: got %v, want ErrUnauthenticated", err)
	}

	_, err = svc.Login(ctx, "nobody@example.com", "password123")
	if err == nil {
		t.Fatal("expected error for unknown user, got nil")
	}
	if !isErr(err, service.ErrUnauthenticated) {
		t.Errorf("unknown user: got %v, want ErrUnauthenticated", err)
	}
}

func TestAuthService_Signup_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	result, err := svc.Signup(ctx, service.SignupParams{
		Email:    "owner@company.com",
		Password: "strongpassword",
	})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if result.RawKey == "" {
		t.Error("signup: raw key is empty")
	}
	if result.Email != "owner@company.com" {
		t.Errorf("signup email = %q, want %q", result.Email, "owner@company.com")
	}
	if result.Role != string(store.UserRoleOwner) {
		t.Errorf("signup role = %q, want %q", result.Role, string(store.UserRoleOwner))
	}
	if result.TenantUID == "" {
		t.Error("signup: tenant uid is empty")
	}
}

func TestAuthService_Signup_DuplicateEmail(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "owner@company.com", "password123")

	_, err = svc.Signup(ctx, service.SignupParams{
		Email:    "owner@company.com",
		Password: "password123",
	})
	if err == nil {
		t.Fatal("expected ErrConflict for duplicate email, got nil")
	}
	if !isErr(err, service.ErrConflict) {
		t.Errorf("duplicate email: got %v, want ErrConflict", err)
	}
}

func TestAuthService_AcceptInvite_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	owner := signupUser(t, svc, "owner@company.com", "password123")

	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "owner@company.com")
	if err != nil {
		t.Fatalf("lookup owner: %v", err)
	}
	tenantID := tenantOf(t, ctx, pc, ownerUser)

	rawToken := seedInvitation(t, ctx, pc, tenantID, "invited@company.com",
		store.UserRoleViewer, pgtype.Int4{Int32: ownerUser.ID, Valid: true})

	result, err := svc.AcceptInvite(ctx, service.AcceptInviteParams{
		Token:    rawToken,
		Password: "newpassword",
	})
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}
	if result.RawKey == "" {
		t.Error("accept invite: raw key is empty")
	}
	if result.Email != "invited@company.com" {
		t.Errorf("accept invite email = %q, want %q", result.Email, "invited@company.com")
	}
	if result.Role != string(store.UserRoleViewer) {
		t.Errorf("accept invite role = %q, want %q", result.Role, string(store.UserRoleViewer))
	}
	// Key should differ from the owner's.
	if result.RawKey == owner.RawKey {
		t.Error("accept invite key should be distinct from owner's key")
	}
}

func TestAuthService_InviteContextFromToken_InviterEmail(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "owner@company.com", "password123")
	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "owner@company.com")
	if err != nil {
		t.Fatalf("lookup owner: %v", err)
	}

	t.Run("populates inviter email", func(t *testing.T) {
		token := seedInvitation(t, ctx, pc, tenantOf(t, ctx, pc, ownerUser), "invited@company.com",
			store.UserRoleViewer, pgtype.Int4{Int32: ownerUser.ID, Valid: true})
		ic, err := svc.InviteContextFromToken(ctx, token)
		if err != nil {
			t.Fatalf("invite context: %v", err)
		}
		if ic.InviterEmail != "owner@company.com" {
			t.Errorf("inviter email = %q, want owner@company.com", ic.InviterEmail)
		}
		if ic.InviteeEmail != "invited@company.com" {
			t.Errorf("invitee email = %q, want invited@company.com", ic.InviteeEmail)
		}
	})

	t.Run("empty when inviter unset", func(t *testing.T) {
		token := seedInvitation(t, ctx, pc, tenantOf(t, ctx, pc, ownerUser), "noinviter@company.com",
			store.UserRoleViewer, pgtype.Int4{})
		ic, err := svc.InviteContextFromToken(ctx, token)
		if err != nil {
			t.Fatalf("invite context: %v", err)
		}
		if ic.InviterEmail != "" {
			t.Errorf("inviter email = %q, want empty", ic.InviterEmail)
		}
	})
}

func TestAuthService_AcceptInvite_InvalidToken(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)

	_, err = svc.AcceptInvite(ctx, service.AcceptInviteParams{
		Token:    "bogus-token-that-does-not-exist",
		Password: "password123",
	})
	if err == nil {
		t.Fatal("expected ErrNotFound for invalid token, got nil")
	}
	if !isErr(err, service.ErrNotFound) {
		t.Errorf("invalid token: got %v, want ErrNotFound", err)
	}
}

func TestAuthService_AcceptInvite_DuplicateEmail(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	// Register a user in their own tenant first.
	signupUser(t, svc, "existing@company.com", "password123")

	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "existing@company.com")
	if err != nil {
		t.Fatalf("lookup owner: %v", err)
	}
	tenantID := tenantOf(t, ctx, pc, ownerUser)

	// Seed an invitation for the already-registered email in the same tenant.
	rawToken := seedInvitation(t, ctx, pc, tenantID, "existing@company.com",
		store.UserRoleViewer, pgtype.Int4{Int32: ownerUser.ID, Valid: true})

	_, err = svc.AcceptInvite(ctx, service.AcceptInviteParams{
		Token:    rawToken,
		Password: "newpassword",
	})
	if err == nil {
		t.Fatal("expected ErrConflict for duplicate email, got nil")
	}
	if !isErr(err, service.ErrConflict) {
		t.Errorf("duplicate email on accept invite: got %v, want ErrConflict", err)
	}
}

func TestAuthService_Session_MintAndResolve(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signup := signupUser(t, svc, "user@example.com", "password123")

	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	p := &auth.Principal{
		UserID:   ownerUser.ID,
		TenantID: tenantOf(t, ctx, pc, ownerUser),
		Email:    "user@example.com",
		Role:     roleOf(t, ctx, pc, ownerUser),
	}
	_ = signup

	rawToken, expiresAt, err := svc.MintSession(ctx, p, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}
	if rawToken == "" {
		t.Error("mint session: raw token is empty")
	}
	if expiresAt.IsZero() {
		t.Error("mint session: expiresAt is zero")
	}
	if !expiresAt.After(time.Now()) {
		t.Error("mint session: expiresAt is in the past")
	}

	// Verify the raw token is NOT stored in the DB (only its hash is).
	var hash string
	err = pc.Pool.QueryRow(
		ctx,
		`SELECT token_hash FROM sessions ORDER BY created_at DESC LIMIT 1`,
	).Scan(&hash)
	if err != nil {
		t.Fatalf("query session hash: %v", err)
	}
	if hash == rawToken {
		t.Error("stored token_hash must not equal the raw token")
	}
	expectedHash := auth.HashToken(rawToken)
	if hash != expectedHash {
		t.Errorf("stored hash = %q, want %q", hash, expectedHash)
	}

	// Resolve the session.
	principal, err := svc.ResolveSession(ctx, rawToken)
	if err != nil {
		t.Fatalf("resolve session: %v", err)
	}
	if principal.UserID != p.UserID {
		t.Errorf("resolved user_id = %d, want %d", principal.UserID, p.UserID)
	}
	if principal.TenantID != p.TenantID {
		t.Errorf("resolved tenant_id = %d, want %d", principal.TenantID, p.TenantID)
	}
	if principal.Email != p.Email {
		t.Errorf("resolved email = %q, want %q", principal.Email, p.Email)
	}
	if principal.Role != p.Role {
		t.Errorf("resolved role = %q, want %q", principal.Role, p.Role)
	}
}

func TestAuthService_Session_LastUsedAtAdvances(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "user@example.com", "password123")

	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	p := &auth.Principal{
		UserID:   ownerUser.ID,
		TenantID: tenantOf(t, ctx, pc, ownerUser),
		Email:    "user@example.com",
		Role:     roleOf(t, ctx, pc, ownerUser),
	}

	rawToken, _, err := svc.MintSession(ctx, p, "", "")
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}

	before := time.Now().Add(-2 * time.Second).Truncate(time.Second)
	if _, err := pc.Pool.Exec(
		ctx,
		`UPDATE sessions SET last_used_at = $1 WHERE token_hash = $2`,
		before,
		auth.HashToken(rawToken),
	); err != nil {
		t.Fatalf("backdate last_used_at: %v", err)
	}

	var storedBefore time.Time
	err = pc.Pool.QueryRow(
		ctx,
		`SELECT last_used_at FROM sessions WHERE token_hash = $1`, auth.HashToken(rawToken),
	).Scan(&storedBefore)
	if err != nil {
		t.Fatalf("query last_used_at before: %v", err)
	}

	if _, err := svc.ResolveSession(ctx, rawToken); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	var after time.Time
	err = pc.Pool.QueryRow(
		ctx,
		`SELECT last_used_at FROM sessions WHERE token_hash = $1`, auth.HashToken(rawToken),
	).Scan(&after)
	if err != nil {
		t.Fatalf("query last_used_at after: %v", err)
	}

	if !after.After(storedBefore) {
		t.Errorf("last_used_at did not advance: before=%v after=%v", storedBefore, after)
	}
}

func TestAuthService_Session_ExpiredToken(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "user@example.com", "password123")

	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}

	// Insert an already-expired session directly.
	rawToken, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	_, err = pc.Pool.Exec(
		ctx,
		`INSERT INTO sessions (user_id, tenant_id, token_hash, expires_at)
		 VALUES ($1, $2, $3, NOW() - INTERVAL '1 hour')`,
		ownerUser.ID, tenantOf(t, ctx, pc, ownerUser), auth.HashToken(rawToken),
	)
	if err != nil {
		t.Fatalf("insert expired session: %v", err)
	}

	_, err = svc.ResolveSession(ctx, rawToken)
	if err == nil {
		t.Fatal("expected ErrUnauthenticated for expired session, got nil")
	}
	if !isErr(err, service.ErrUnauthenticated) {
		t.Errorf("expired token: got %v, want ErrUnauthenticated", err)
	}
}

func TestAuthService_Session_BogusToken(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)

	_, err = svc.ResolveSession(ctx, "completely-bogus-token")
	if err == nil {
		t.Fatal("expected ErrUnauthenticated for bogus token, got nil")
	}
	if !isErr(err, service.ErrUnauthenticated) {
		t.Errorf("bogus token: got %v, want ErrUnauthenticated", err)
	}
}

func TestAuthService_Session_Revoke(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "user@example.com", "password123")

	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	p := &auth.Principal{
		UserID:   ownerUser.ID,
		TenantID: tenantOf(t, ctx, pc, ownerUser),
		Email:    "user@example.com",
		Role:     roleOf(t, ctx, pc, ownerUser),
	}

	rawToken, _, err := svc.MintSession(ctx, p, "", "")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Verify it resolves before revoke.
	if _, err := svc.ResolveSession(ctx, rawToken); err != nil {
		t.Fatalf("resolve before revoke: %v", err)
	}

	// Revoke.
	if err := svc.RevokeSession(ctx, rawToken); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Row must be gone.
	var count int
	err = pc.Pool.QueryRow(
		ctx,
		`SELECT COUNT(*) FROM sessions WHERE token_hash = $1`, auth.HashToken(rawToken),
	).Scan(&count)
	if err != nil {
		t.Fatalf("count after revoke: %v", err)
	}
	if count != 0 {
		t.Errorf("session row still exists after revoke, count = %d", count)
	}

	// Resolve after revoke → ErrUnauthenticated.
	_, err = svc.ResolveSession(ctx, rawToken)
	if err == nil {
		t.Fatal("expected ErrUnauthenticated after revoke, got nil")
	}
	if !isErr(err, service.ErrUnauthenticated) {
		t.Errorf("after revoke: got %v, want ErrUnauthenticated", err)
	}

	// Second revoke is idempotent.
	if err := svc.RevokeSession(ctx, rawToken); err != nil {
		t.Errorf("second revoke should be idempotent, got: %v", err)
	}
}

func TestAuthService_Session_RawTokenNotStored(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "user@example.com", "password123")

	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	p := &auth.Principal{
		UserID:   ownerUser.ID,
		TenantID: tenantOf(t, ctx, pc, ownerUser),
		Email:    "user@example.com",
		Role:     roleOf(t, ctx, pc, ownerUser),
	}

	rawToken, _, err := svc.MintSession(ctx, p, "Mozilla/5.0", "192.168.1.1")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Scan ALL text columns for the raw token — it must not appear anywhere.
	var count int
	err = pc.Pool.QueryRow(
		ctx,
		`SELECT COUNT(*) FROM sessions
		 WHERE token_hash = $1 OR user_agent = $1 OR ip = $1`,
		rawToken,
	).Scan(&count)
	if err != nil {
		t.Fatalf("scan for raw token: %v", err)
	}
	if count != 0 {
		t.Error("raw token found stored in the sessions table — only the hash must be stored")
	}
}

func TestAuthService_Authenticate_Valid(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "auth@example.com", "password123")

	p, err := svc.Authenticate(ctx, "auth@example.com", "password123")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p == nil {
		t.Fatal("authenticate: principal is nil")
	}
	if p.Email != "auth@example.com" {
		t.Errorf("authenticate email = %q, want %q", p.Email, "auth@example.com")
	}
	if p.UserID == 0 {
		t.Error("authenticate: UserID is zero")
	}
}

func TestAuthService_Authenticate_Invalid(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "auth@example.com", "password123")

	_, err = svc.Authenticate(ctx, "auth@example.com", "wrongpassword")
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if !isErr(err, service.ErrUnauthenticated) {
		t.Errorf("wrong password: got %v, want ErrUnauthenticated", err)
	}
}

func TestAuthService_AcceptInviteWeb_Valid(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "owner@company.com", "password123")

	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "owner@company.com")
	if err != nil {
		t.Fatalf("lookup owner: %v", err)
	}
	tenantID := tenantOf(t, ctx, pc, ownerUser)

	rawToken := seedInvitation(t, ctx, pc, tenantID, "web-invited@company.com",
		store.UserRoleViewer, pgtype.Int4{Int32: ownerUser.ID, Valid: true})

	p, err := svc.AcceptInviteWeb(ctx, service.AcceptInviteParams{
		Token:    rawToken,
		Password: "newpassword",
	})
	if err != nil {
		t.Fatalf("accept invite web: %v", err)
	}
	if p == nil {
		t.Fatal("accept invite web: principal is nil")
	}
	if p.Email != "web-invited@company.com" {
		t.Errorf("accept invite web email = %q, want %q", p.Email, "web-invited@company.com")
	}
	if p.Role != string(store.UserRoleViewer) {
		t.Errorf("accept invite web role = %q, want %q", p.Role, string(store.UserRoleViewer))
	}

	// Confirm no api_keys row was created for this user.
	var count int
	err = pc.Pool.QueryRow(
		ctx,
		`SELECT COUNT(*) FROM api_keys WHERE user_id = $1`, p.UserID,
	).Scan(&count)
	if err != nil {
		t.Fatalf("count api_keys: %v", err)
	}
	if count != 0 {
		t.Errorf("AcceptInviteWeb must not create API key rows; found %d", count)
	}
}

func TestAuthService_AcceptInviteWeb_InvalidToken(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)

	_, err = svc.AcceptInviteWeb(ctx, service.AcceptInviteParams{
		Token:    "bogus-token-that-does-not-exist",
		Password: "password123",
	})
	if err == nil {
		t.Fatal("expected ErrNotFound for invalid token, got nil")
	}
	if !isErr(err, service.ErrNotFound) {
		t.Errorf("invalid token: got %v, want ErrNotFound", err)
	}
}

// isErr is a small helper so test assertions stay concise.
func isErr(err, target error) bool {
	return errors.Is(err, target)
}

// newAuthSvcWithEmailer builds a real AuthService whose email-enqueue seam is the
// returned recording fakeScheduler (defined in domains_test.go), so reset-request
// tests can assert what was queued.
func newAuthSvcWithEmailer(
	t *testing.T,
	pc *testhelpers.PostgresContainer,
) (*service.AuthService, *fakeScheduler) {
	t.Helper()
	cfg := config.AppConfig()
	cfg.Auth.BcryptCost = 4
	cfg.Auth.SessionTTL = 720 * time.Hour
	cfg.Auth.ResetTTL = time.Hour

	provider, err := auth.NewProvider(auth.Config{Provider: "local", BcryptCost: 4}, pc.Queries)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	sched := &fakeScheduler{}
	svc := service.NewWithScheduler(
		cfg,
		slog.New(slog.DiscardHandler),
		pc.Queries,
		pc.Pool,
		sched,
		provider,
	)
	return svc.AuthService(), sched
}

// seedResetToken inserts a live password-reset token and returns the raw token.
func seedResetToken(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	userID int32,
	expiresAt time.Time,
) string {
	t.Helper()
	raw, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("generate reset token: %v", err)
	}
	_, err = pc.Queries.PasswordResetTokenCreate(ctx, store.PasswordResetTokenCreateParams{
		UserID:    userID,
		TokenHash: auth.HashToken(raw),
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
	if err != nil {
		t.Fatalf("seed reset token: %v", err)
	}
	return raw
}

func TestAuthService_SignupWeb_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	p, err := svc.SignupWeb(ctx, service.SignupParams{
		Email:    "owner@example.com",
		Password: "password123",
		Name:     "Owner",
	})
	if err != nil {
		t.Fatalf("signup web: %v", err)
	}
	if p.Email != "owner@example.com" {
		t.Errorf("principal email = %q, want owner@example.com", p.Email)
	}
	if p.Role != string(store.UserRoleOwner) {
		t.Errorf("principal role = %q, want owner", p.Role)
	}
	if p.UserID == 0 || p.TenantID == 0 {
		t.Errorf("principal ids unset: %+v", p)
	}
	// New password authenticates.
	if _, err := svc.Authenticate(ctx, "owner@example.com", "password123"); err != nil {
		t.Errorf("authenticate after signup web: %v", err)
	}
	// No API key is minted by the web flow.
	var keyCount int
	if err := pc.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_keys`).Scan(&keyCount); err != nil {
		t.Fatalf("count api keys: %v", err)
	}
	if keyCount != 0 {
		t.Errorf("api key count = %d, want 0 (web signup mints a session, not a key)", keyCount)
	}
}

func TestAuthService_SignupWeb_DuplicateEmail(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "dup@example.com", "password123")

	_, err = svc.SignupWeb(
		ctx,
		service.SignupParams{Email: "dup@example.com", Password: "password123"},
	)
	if !isErr(err, service.ErrConflict) {
		t.Errorf("duplicate signup web: got %v, want ErrConflict", err)
	}
}

func TestAuthService_SignupWeb_SendsWelcomeEmail(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc, sched := newAuthSvcWithEmailer(t, pc)
	if _, err := svc.SignupWeb(ctx, service.SignupParams{
		Email:      "welcome@example.com",
		Password:   "password123",
		TenantName: "Acme",
	}); err != nil {
		t.Fatalf("signup web: %v", err)
	}

	if len(sched.emails) != 1 {
		t.Fatalf("enqueued %d emails, want 1 welcome email", len(sched.emails))
	}
	msg := sched.emails[0]
	if msg.To != "welcome@example.com" {
		t.Errorf("welcome email To = %q, want welcome@example.com", msg.To)
	}
	if !strings.Contains(strings.ToLower(msg.Subject), "welcome") {
		t.Errorf("welcome email subject = %q, want a welcome subject", msg.Subject)
	}
	if !strings.Contains(msg.HTML, "Acme") {
		t.Errorf("welcome email should mention the workspace name, got: %q", msg.HTML)
	}
}

func TestAuthService_Signup_SendsWelcomeEmail(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc, sched := newAuthSvcWithEmailer(t, pc)
	if _, err := svc.Signup(ctx, service.SignupParams{
		Email:    "apiwelcome@example.com",
		Password: "password123",
	}); err != nil {
		t.Fatalf("signup: %v", err)
	}
	if len(sched.emails) != 1 {
		t.Fatalf("enqueued %d emails, want 1 welcome email", len(sched.emails))
	}
	if !strings.Contains(strings.ToLower(sched.emails[0].Subject), "welcome") {
		t.Errorf("welcome email subject = %q, want a welcome subject", sched.emails[0].Subject)
	}
}

func TestAuthService_RequestPasswordReset_UnknownEmail(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc, sched := newAuthSvcWithEmailer(t, pc)

	if err := svc.RequestPasswordReset(ctx, "nobody@example.com", "https://x"); err != nil {
		t.Fatalf("request reset for unknown email should not error: %v", err)
	}
	var tokCount int
	if err := pc.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM password_reset_tokens`).Scan(&tokCount); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if tokCount != 0 {
		t.Errorf("token count = %d, want 0 (no token for unknown email)", tokCount)
	}
	if len(sched.emails) != 0 {
		t.Errorf("enqueued %d emails for unknown address, want 0", len(sched.emails))
	}
}

func TestAuthService_RequestPasswordReset_KnownEmail(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc, sched := newAuthSvcWithEmailer(t, pc)
	signupUser(t, svc, "real@example.com", "password123")
	// Drop the welcome email enqueued by signup so we assert on the reset email only.
	sched.emails = nil

	if err := svc.RequestPasswordReset(ctx, "real@example.com", "https://app.test"); err != nil {
		t.Fatalf("request reset: %v", err)
	}
	var tokCount int
	if err := pc.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM password_reset_tokens`).Scan(&tokCount); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if tokCount != 1 {
		t.Fatalf("token count = %d, want 1", tokCount)
	}
	if len(sched.emails) != 1 {
		t.Fatalf("enqueued %d emails, want 1", len(sched.emails))
	}
	msg := sched.emails[0]
	if msg.To != "real@example.com" {
		t.Errorf("email To = %q, want real@example.com", msg.To)
	}
	if !strings.Contains(msg.HTML, "https://app.test/app/reset-password?token=") {
		t.Errorf("email HTML missing reset link, got: %q", msg.HTML)
	}
}

func TestAuthService_ResetPassword_HappyPath(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "reset@example.com", "oldpassword")
	user, err := pc.Queries.UserGetByEmail(ctx, "reset@example.com")
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	p := &auth.Principal{
		UserID:   user.ID,
		TenantID: tenantOf(t, ctx, pc, user),
		Email:    user.Email,
		Role:     roleOf(t, ctx, pc, user),
	}
	// Two live sessions that must be revoked by the reset.
	if _, _, err := svc.MintSession(ctx, p, "", ""); err != nil {
		t.Fatalf("mint session 1: %v", err)
	}
	if _, _, err := svc.MintSession(ctx, p, "", ""); err != nil {
		t.Fatalf("mint session 2: %v", err)
	}

	rawToken := seedResetToken(t, ctx, pc, user.ID, time.Now().Add(time.Hour))

	if err := svc.ResetPassword(ctx, rawToken, "brandnewpass"); err != nil {
		t.Fatalf("reset password: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "reset@example.com", "brandnewpass"); err != nil {
		t.Errorf("authenticate with new password: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "reset@example.com", "oldpassword"); !isErr(
		err,
		service.ErrUnauthenticated,
	) {
		t.Errorf("old password should be rejected: got %v", err)
	}
	var sessCount int
	if err := pc.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = $1`, user.ID).Scan(&sessCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessCount != 0 {
		t.Errorf("session count after reset = %d, want 0 (all revoked)", sessCount)
	}
	// Token is single-use.
	if err := svc.ResetPassword(ctx, rawToken, "anotherpass1"); !isErr(err, service.ErrNotFound) {
		t.Errorf("reusing token: got %v, want ErrNotFound", err)
	}
}

func TestAuthService_ResetPassword_InvalidToken(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	if err := svc.ResetPassword(ctx, "bogus-token", "password123"); !isErr(
		err,
		service.ErrNotFound,
	) {
		t.Errorf("invalid token: got %v, want ErrNotFound", err)
	}
}

func TestAuthService_ResetPassword_ExpiredToken(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "exp@example.com", "oldpassword")
	user, err := pc.Queries.UserGetByEmail(ctx, "exp@example.com")
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	rawToken := seedResetToken(t, ctx, pc, user.ID, time.Now().Add(-time.Hour))

	if err := svc.ResetPassword(ctx, rawToken, "brandnewpass"); !isErr(err, service.ErrNotFound) {
		t.Errorf("expired token: got %v, want ErrNotFound", err)
	}
}

func TestAuthService_ResetPassword_WeakPassword(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "weak@example.com", "oldpassword")
	user, err := pc.Queries.UserGetByEmail(ctx, "weak@example.com")
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	rawToken := seedResetToken(t, ctx, pc, user.ID, time.Now().Add(time.Hour))

	if err := svc.ResetPassword(ctx, rawToken, "short"); !isErr(err, service.ErrInvalidInput) {
		t.Errorf("weak password: got %v, want ErrInvalidInput", err)
	}
}

// TestAuthService_CreateWorkspace verifies an existing account can spin up an
// additional workspace, becoming its owner and ending up with multiple memberships.
func TestAuthService_CreateWorkspace(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "owner@a.com", "supersecret")
	p := principalForEmail(t, ctx, pc, "owner@a.com")

	ws, err := svc.CreateWorkspace(ctx, p, "Second Workspace")
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if ws.TenantUID == "" || ws.TenantID == 0 {
		t.Fatalf("create workspace: empty identifiers %+v", ws)
	}

	role, err := pc.Queries.MembershipGetRole(ctx, store.MembershipGetRoleParams{
		UserID:   p.UserID,
		TenantID: ws.TenantID,
	})
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if role != store.UserRoleOwner {
		t.Errorf("workspace role = %q, want owner", role)
	}

	memberships, err := svc.ListMemberships(ctx, p)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 2 {
		t.Errorf("memberships = %d, want 2 (original + new workspace)", len(memberships))
	}
}

// TestAuthService_AttachInviteWeb verifies an already-registered user can accept an
// invitation to another tenant while authenticated, gaining a second membership,
// and that an invite addressed to a different identity is refused.
func TestAuthService_AttachInviteWeb(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "owner@a.com", "supersecret")  // tenant A
	signupUser(t, svc, "member@b.com", "supersecret") // their own tenant B
	pOwnerA := principalForEmail(t, ctx, pc, "owner@a.com")
	pMemberB := principalForEmail(t, ctx, pc, "member@b.com")
	tenantA := pOwnerA.TenantID

	token := seedInvitation(t, ctx, pc, tenantA, "member@b.com",
		store.UserRoleViewer, pgtype.Int4{Int32: pOwnerA.UserID, Valid: true})

	// An invite addressed to member@b.com cannot be claimed by a different identity.
	if _, err := svc.AttachInviteWeb(ctx, pOwnerA, token); !isErr(err, service.ErrForbidden) {
		t.Errorf("wrong-identity attach: got %v, want ErrForbidden", err)
	}

	// The matching identity attaches and gains a membership in tenant A.
	got, err := svc.AttachInviteWeb(ctx, pMemberB, token)
	if err != nil {
		t.Fatalf("attach invite: %v", err)
	}
	if got != tenantA {
		t.Errorf("attach tenant = %d, want %d", got, tenantA)
	}
	role, err := pc.Queries.MembershipGetRole(ctx, store.MembershipGetRoleParams{
		UserID:   pMemberB.UserID,
		TenantID: tenantA,
	})
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if role != store.UserRoleViewer {
		t.Errorf("attached role = %q, want viewer", role)
	}

	// Re-attaching is a conflict (already a member).
	if _, err := svc.AttachInviteWeb(ctx, pMemberB, token); !isErr(err, service.ErrConflict) {
		t.Errorf("re-attach: got %v, want ErrConflict", err)
	}
}

// TestAuthService_SwitchTenant_NonMemberForbidden verifies switching to a tenant
// the caller does not belong to is refused.
func TestAuthService_SwitchTenant_NonMemberForbidden(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	svc := newAuthSvc(t, pc)
	signupUser(t, svc, "owner@a.com", "supersecret")
	signupUser(t, svc, "owner@b.com", "supersecret")
	pA := principalForEmail(t, ctx, pc, "owner@a.com")
	bUser, err := pc.Queries.UserGetByEmail(ctx, "owner@b.com")
	if err != nil {
		t.Fatalf("b lookup: %v", err)
	}
	tenantB, err := pc.Queries.MembershipsListForUser(ctx, bUser.ID)
	if err != nil || len(tenantB) == 0 {
		t.Fatalf("tenant B memberships: %v", err)
	}

	if err := svc.SwitchTenant(ctx, pA, tenantB[0].TenantUid, "no-session"); !isErr(err, service.ErrForbidden) {
		t.Errorf("non-member switch: got %v, want ErrForbidden", err)
	}
}
