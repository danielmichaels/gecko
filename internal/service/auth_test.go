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
	tenantID := ownerUser.TenantID.Int32

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

func TestAuthService_AcceptInvite_InvalidToken(t *testing.T) {
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
	tenantID := ownerUser.TenantID.Int32

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
		TenantID: ownerUser.TenantID.Int32,
		Email:    "user@example.com",
		Role:     string(ownerUser.Role),
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
		TenantID: ownerUser.TenantID.Int32,
		Email:    "user@example.com",
		Role:     string(ownerUser.Role),
	}

	rawToken, _, err := svc.MintSession(ctx, p, "", "")
	if err != nil {
		t.Fatalf("mint session: %v", err)
	}

	// Record initial last_used_at.
	var before time.Time
	err = pc.Pool.QueryRow(
		ctx,
		`SELECT last_used_at FROM sessions WHERE token_hash = $1`, auth.HashToken(rawToken),
	).Scan(&before)
	if err != nil {
		t.Fatalf("query last_used_at before: %v", err)
	}

	// Ensure at least 1 second passes so the TIMESTAMP(0) resolution can show a change.
	time.Sleep(1100 * time.Millisecond)

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

	if !after.After(before) {
		t.Errorf("last_used_at did not advance: before=%v after=%v", before, after)
	}
}

func TestAuthService_Session_ExpiredToken(t *testing.T) {
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
		ownerUser.ID, ownerUser.TenantID.Int32, auth.HashToken(rawToken),
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
		TenantID: ownerUser.TenantID.Int32,
		Email:    "user@example.com",
		Role:     string(ownerUser.Role),
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
		TenantID: ownerUser.TenantID.Int32,
		Email:    "user@example.com",
		Role:     string(ownerUser.Role),
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
	tenantID := ownerUser.TenantID.Int32

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
