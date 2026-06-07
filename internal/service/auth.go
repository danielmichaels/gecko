package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// AuthService exposes authentication and session business logic.
type AuthService struct {
	*Service
}

// LoginResult holds the outcome of a successful Login call.
type LoginResult struct {
	RawKey    string
	ExpiresAt pgtype.Timestamptz
	Email     string
	Role      string
}

// SignupResult holds the outcome of a successful Signup call.
type SignupResult struct {
	RawKey    string
	ExpiresAt pgtype.Timestamptz
	Email     string
	Role      string
	TenantUID string
}

// AcceptInviteResult holds the outcome of a successful AcceptInvite call.
type AcceptInviteResult struct {
	RawKey    string
	ExpiresAt pgtype.Timestamptz
	Email     string
	Role      string
}

// Login verifies credentials and mints an API key for CLI/programmatic use.
// Returns ErrUnauthenticated for invalid credentials.
func (s *AuthService) Login(ctx context.Context, email, password string) (LoginResult, error) {
	email = normaliseEmail(email)
	p, err := s.AuthProvider.Authenticate(ctx, auth.Credentials{
		Email:    email,
		Password: password,
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("%w: authenticate failed", ErrUnauthenticated)
	}
	key, _, exp, err := s.mintAPIKey(ctx, s.DB, p.TenantID, p.UserID, "cli-login")
	if err != nil {
		return LoginResult{}, fmt.Errorf("login: mint key: %w", err)
	}
	return LoginResult{
		RawKey:    key.Raw,
		ExpiresAt: exp,
		Email:     p.Email,
		Role:      p.Role,
	}, nil
}

// SignupParams holds the caller-supplied fields for tenant creation.
type SignupParams struct {
	Email      string
	Password   string
	Name       string
	TenantName string
}

// Signup creates a new tenant and its first owner, then mints a key.
// Duplicate email raises ErrConflict. SignupEnabled is NOT checked here;
// that policy gate stays in the handler to preserve the exact 403 message.
func (s *AuthService) Signup(ctx context.Context, params SignupParams) (SignupResult, error) {
	email := normaliseEmail(params.Email)
	if _, err := s.DB.UserGetByEmail(ctx, email); err == nil {
		return SignupResult{}, fmt.Errorf("%w: email already registered", ErrConflict)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return SignupResult{}, fmt.Errorf("signup: lookup: %w", err)
	}
	hash, err := auth.HashPassword(params.Password, s.Conf.Auth.BcryptCost)
	if err != nil {
		return SignupResult{}, fmt.Errorf("signup: hash password: %w", err)
	}
	tenantName := strings.TrimSpace(params.TenantName)
	if tenantName == "" {
		tenantName = email
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return SignupResult{}, fmt.Errorf("signup: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	tenant, err := st.TenantCreate(ctx, tenantName)
	if err != nil {
		return SignupResult{}, fmt.Errorf("signup: create tenant: %w", err)
	}
	user, err := st.UserProvision(ctx, store.UserProvisionParams{
		TenantID: pgtype.Int4{Int32: tenant.ID, Valid: true},
		Email:    email,
		Name:     pgtype.Text{String: params.Name, Valid: params.Name != ""},
		Role:     store.UserRoleOwner,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return SignupResult{}, fmt.Errorf("%w: email already registered", ErrConflict)
		}
		return SignupResult{}, fmt.Errorf("signup: provision user: %w", err)
	}
	if err := st.UserCredentialUpsert(ctx, store.UserCredentialUpsertParams{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		return SignupResult{}, fmt.Errorf("signup: credential upsert: %w", err)
	}
	key, _, exp, err := s.mintAPIKey(ctx, st, tenant.ID, user.ID, "signup")
	if err != nil {
		return SignupResult{}, fmt.Errorf("signup: mint key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return SignupResult{}, fmt.Errorf("signup: commit: %w", err)
	}
	return SignupResult{
		RawKey:    key.Raw,
		ExpiresAt: exp,
		Email:     email,
		Role:      string(store.UserRoleOwner),
		TenantUID: tenant.Uid,
	}, nil
}

// AcceptInviteParams holds the caller-supplied fields for accepting an invitation.
type AcceptInviteParams struct {
	Token    string
	Password string
	Name     string
}

// AcceptInvite consumes an invitation token, creating the user with the
// invited role in the inviting tenant, and mints a key.
// Invalid/expired token → ErrNotFound. Duplicate email → ErrConflict.
func (s *AuthService) AcceptInvite(ctx context.Context, params AcceptInviteParams) (AcceptInviteResult, error) {
	inv, err := s.DB.InvitationGetByTokenHash(ctx, auth.HashToken(params.Token))
	if err != nil {
		// Deliberately opaque: expired and invalid tokens both return not-found
		// so callers cannot distinguish the two cases.
		return AcceptInviteResult{}, fmt.Errorf("%w: invalid or expired invitation", ErrNotFound)
	}
	hash, err := auth.HashPassword(params.Password, s.Conf.Auth.BcryptCost)
	if err != nil {
		return AcceptInviteResult{}, fmt.Errorf("accept invite: hash password: %w", err)
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return AcceptInviteResult{}, fmt.Errorf("accept invite: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	user, err := st.UserProvision(ctx, store.UserProvisionParams{
		TenantID: pgtype.Int4{Int32: inv.TenantID, Valid: true},
		Email:    inv.Email,
		Name:     pgtype.Text{String: params.Name, Valid: params.Name != ""},
		Role:     inv.Role,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return AcceptInviteResult{}, fmt.Errorf("%w: email already registered", ErrConflict)
		}
		return AcceptInviteResult{}, fmt.Errorf("accept invite: provision user: %w", err)
	}
	if err := st.UserCredentialUpsert(ctx, store.UserCredentialUpsertParams{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		return AcceptInviteResult{}, fmt.Errorf("accept invite: credential upsert: %w", err)
	}
	if err := st.InvitationMarkAccepted(ctx, inv.ID); err != nil {
		return AcceptInviteResult{}, fmt.Errorf("accept invite: mark accepted: %w", err)
	}
	key, _, exp, err := s.mintAPIKey(ctx, st, inv.TenantID, user.ID, "invite-accept")
	if err != nil {
		return AcceptInviteResult{}, fmt.Errorf("accept invite: mint key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return AcceptInviteResult{}, fmt.Errorf("accept invite: commit: %w", err)
	}
	return AcceptInviteResult{
		RawKey:    key.Raw,
		ExpiresAt: exp,
		Email:     inv.Email,
		Role:      string(inv.Role),
	}, nil
}

// Logout revokes the API key that authenticated the request. Ignores missing rows.
func (s *AuthService) Logout(ctx context.Context, p *auth.Principal, apiKeyUID string) error {
	_, err := s.DB.ApiKeyRevoke(ctx, store.ApiKeyRevokeParams{
		Uid:      apiKeyUID,
		TenantID: p.TenantID,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("logout: revoke key: %w", err)
	}
	return nil
}

// MintSession generates a new session token, persists only its hash, and returns
// the raw token and expiry. The raw token is placed in the response cookie by the
// caller and is never stored.
func (s *AuthService) MintSession(
	ctx context.Context,
	p *auth.Principal,
	userAgent, ip string,
) (rawToken string, expiresAt time.Time, err error) {
	rawToken, err = auth.GenerateToken()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint session: generate token: %w", err)
	}
	expiresAt = time.Now().Add(s.Conf.Auth.SessionTTL)
	_, err = s.DB.SessionCreate(ctx, store.SessionCreateParams{
		UserID:    p.UserID,
		TenantID:  p.TenantID,
		TokenHash: auth.HashToken(rawToken),
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
		UserAgent: pgtype.Text{String: userAgent, Valid: userAgent != ""},
		Ip:        pgtype.Text{String: ip, Valid: ip != ""},
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint session: persist: %w", err)
	}
	return rawToken, expiresAt, nil
}

// ResolveSession looks up a session by the raw token, slides last_used_at, and
// returns the associated Principal. Returns ErrUnauthenticated for unknown or
// expired tokens; a touch failure is logged but does not fail resolution.
func (s *AuthService) ResolveSession(ctx context.Context, rawToken string) (*auth.Principal, error) {
	row, err := s.DB.SessionResolve(ctx, auth.HashToken(rawToken))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: session not found or expired", ErrUnauthenticated)
		}
		return nil, fmt.Errorf("resolve session: %w", err)
	}
	if err := s.DB.SessionTouch(ctx, auth.HashToken(rawToken)); err != nil {
		s.Log.Warn("session touch failed", "error", err)
	}
	return &auth.Principal{
		UserID:   row.UserID,
		TenantID: row.TenantID,
		Email:    row.UserEmail,
		Role:     string(row.UserRole),
	}, nil
}

// RevokeSession deletes the session row identified by the raw token.
// Idempotent: revoking an unknown token is not an error.
func (s *AuthService) RevokeSession(ctx context.Context, rawToken string) error {
	if err := s.DB.SessionRevoke(ctx, auth.HashToken(rawToken)); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// mintAPIKey creates and persists an API key for (tenant, user) using q (which may
// be a transaction-scoped Queries), returning the raw key and its expiry. The raw
// secret is returned to the caller once and never stored.
func (s *AuthService) mintAPIKey(
	ctx context.Context,
	q *store.Queries,
	tenantID, userID int32,
	name string,
) (key auth.APIKey, uid string, exp pgtype.Timestamptz, err error) {
	key, err = auth.NewAPIKey()
	if err != nil {
		return auth.APIKey{}, "", pgtype.Timestamptz{}, err
	}
	if ttl := s.Conf.Auth.APIKeyTTL; ttl > 0 {
		exp = pgtype.Timestamptz{Time: time.Now().Add(ttl), Valid: true}
	}
	row, err := q.ApiKeyCreate(ctx, store.ApiKeyCreateParams{
		TenantID:  tenantID,
		UserID:    userID,
		Name:      name,
		Prefix:    key.Prefix,
		KeyHash:   key.KeyHash,
		ExpiresAt: exp,
	})
	if err != nil {
		return auth.APIKey{}, "", pgtype.Timestamptz{}, err
	}
	return key, row.Uid, exp, nil
}

func normaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
