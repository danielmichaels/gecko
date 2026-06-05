package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// authOutput is returned by flows that mint a key for the caller (signup, login,
// accept-invite). The api_key is shown exactly once.
type authOutput struct {
	Body struct {
		APIKey    string     `json:"api_key" doc:"API key — shown once. Store it; it cannot be retrieved again."`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
		Email     string     `json:"email"`
		Role      string     `json:"role"`
		TenantUID string     `json:"tenant_uid,omitempty"`
	}
}

func authToken(key auth.APIKey, exp pgtype.Timestamptz, email, role, tenantUID string) *authOutput {
	out := &authOutput{}
	out.Body.APIKey = key.Raw
	out.Body.Email = email
	out.Body.Role = role
	out.Body.TenantUID = tenantUID
	if exp.Valid {
		t := exp.Time
		out.Body.ExpiresAt = &t
	}
	return out
}

// mintAPIKey creates and persists an API key for (tenant, user) using q (which may
// be a transaction-scoped Queries), returning the raw key and its expiry. The raw
// secret is returned to the caller once and never stored.
func (app *Server) mintAPIKey(
	ctx context.Context,
	q *store.Queries,
	tenantID, userID int32,
	name string,
) (key auth.APIKey, uid string, exp pgtype.Timestamptz, err error) {
	key, err = auth.NewAPIKey()
	if err != nil {
		return auth.APIKey{}, "", pgtype.Timestamptz{}, err
	}
	if ttl := app.Conf.Auth.APIKeyTTL; ttl > 0 {
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

type SignupInput struct {
	Body struct {
		Email      string `json:"email"       required:"true"  format:"email"`
		Password   string `json:"password"    required:"true"  minLength:"8"`
		Name       string `json:"name,omitempty"`
		TenantName string `json:"tenant_name,omitempty" doc:"Display name for the new team; defaults to the email."`
	}
}

// handleSignup creates a new tenant and its first owner, then mints a key. Gated by
// SIGNUP_ENABLED. Single-tenant emails: an already-registered email is rejected 409.
func (app *Server) handleSignup(ctx context.Context, i *SignupInput) (*authOutput, error) {
	if !app.Conf.Auth.SignupEnabled {
		return nil, huma.Error403Forbidden("signup is disabled")
	}
	email := normaliseEmail(i.Body.Email)
	if _, err := app.Db.UserGetByEmail(ctx, email); err == nil {
		return nil, huma.Error409Conflict("email already registered")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, huma.Error500InternalServerError("signup failed", err)
	}
	hash, err := auth.HashPassword(i.Body.Password, app.Conf.Auth.BcryptCost)
	if err != nil {
		return nil, huma.Error500InternalServerError("signup failed", err)
	}
	tenantName := strings.TrimSpace(i.Body.TenantName)
	if tenantName == "" {
		tenantName = email
	}

	tx, err := app.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, huma.Error500InternalServerError("signup failed", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := app.Db.WithTx(tx)

	tenant, err := st.TenantCreate(ctx, tenantName)
	if err != nil {
		return nil, huma.Error500InternalServerError("signup failed", err)
	}
	user, err := st.UserProvision(ctx, store.UserProvisionParams{
		TenantID: pgtype.Int4{Int32: tenant.ID, Valid: true},
		Email:    email,
		Name:     pgtype.Text{String: i.Body.Name, Valid: i.Body.Name != ""},
		Role:     store.UserRoleOwner,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, huma.Error409Conflict("email already registered")
		}
		return nil, huma.Error500InternalServerError("signup failed", err)
	}
	if err := st.UserCredentialUpsert(ctx, store.UserCredentialUpsertParams{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		return nil, huma.Error500InternalServerError("signup failed", err)
	}
	key, _, exp, err := app.mintAPIKey(ctx, st, tenant.ID, user.ID, "signup")
	if err != nil {
		return nil, huma.Error500InternalServerError("signup failed", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, huma.Error500InternalServerError("signup failed", err)
	}
	return authToken(key, exp, email, string(store.UserRoleOwner), tenant.Uid), nil
}

type LoginInput struct {
	Body struct {
		Email    string `json:"email"    required:"true" format:"email"`
		Password string `json:"password" required:"true"`
	}
}

// handleLogin verifies credentials and mints an API key for programmatic/CLI use.
func (app *Server) handleLogin(ctx context.Context, i *LoginInput) (*authOutput, error) {
	email := normaliseEmail(i.Body.Email)
	p, err := app.AuthProvider.Authenticate(ctx, auth.Credentials{
		Email:    email,
		Password: i.Body.Password,
	})
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid credentials")
	}
	key, _, exp, err := app.mintAPIKey(ctx, app.Db, p.TenantID, p.UserID, "cli-login")
	if err != nil {
		return nil, huma.Error500InternalServerError("login failed", err)
	}
	return authToken(key, exp, p.Email, p.Role, ""), nil
}

// handleLogout revokes the API key that authenticated this request.
func (app *Server) handleLogout(ctx context.Context, _ *struct{}) (*struct{}, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	uid, ok := apiKeyUIDFromContext(ctx)
	if !ok {
		return &struct{}{}, nil
	}
	if _, err := app.Db.ApiKeyRevoke(ctx, store.ApiKeyRevokeParams{
		Uid:      uid,
		TenantID: p.TenantID,
	}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, huma.Error500InternalServerError("logout failed", err)
	}
	return &struct{}{}, nil
}

type MeOutput struct {
	Body struct {
		Email    string `json:"email"`
		Role     string `json:"role"`
		UserID   int32  `json:"user_id"`
		TenantID int32  `json:"tenant_id"`
	}
}

// handleMe returns the authenticated caller's identity.
func (app *Server) handleMe(ctx context.Context, _ *struct{}) (*MeOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	out := &MeOutput{}
	out.Body.Email = p.Email
	out.Body.Role = p.Role
	out.Body.UserID = p.UserID
	out.Body.TenantID = p.TenantID
	return out, nil
}

type AcceptInviteInput struct {
	Body struct {
		Token    string `json:"token"    required:"true"`
		Password string `json:"password" required:"true" minLength:"8"`
		Name     string `json:"name,omitempty"`
	}
}

// handleAcceptInvite consumes an invitation token, creating the user (with the
// invited role, in the inviting tenant) and minting a key.
func (app *Server) handleAcceptInvite(
	ctx context.Context,
	i *AcceptInviteInput,
) (*authOutput, error) {
	inv, err := app.Db.InvitationGetByTokenHash(ctx, auth.HashToken(i.Body.Token))
	if err != nil {
		return nil, huma.Error400BadRequest("invalid or expired invitation")
	}
	hash, err := auth.HashPassword(i.Body.Password, app.Conf.Auth.BcryptCost)
	if err != nil {
		return nil, huma.Error500InternalServerError("accept failed", err)
	}

	tx, err := app.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, huma.Error500InternalServerError("accept failed", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := app.Db.WithTx(tx)

	user, err := st.UserProvision(ctx, store.UserProvisionParams{
		TenantID: pgtype.Int4{Int32: inv.TenantID, Valid: true},
		Email:    inv.Email,
		Name:     pgtype.Text{String: i.Body.Name, Valid: i.Body.Name != ""},
		Role:     inv.Role,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, huma.Error409Conflict("email already registered")
		}
		return nil, huma.Error500InternalServerError("accept failed", err)
	}
	if err := st.UserCredentialUpsert(ctx, store.UserCredentialUpsertParams{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		return nil, huma.Error500InternalServerError("accept failed", err)
	}
	if err := st.InvitationMarkAccepted(ctx, inv.ID); err != nil {
		return nil, huma.Error500InternalServerError("accept failed", err)
	}
	key, _, exp, err := app.mintAPIKey(ctx, st, inv.TenantID, user.ID, "invite-accept")
	if err != nil {
		return nil, huma.Error500InternalServerError("accept failed", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, huma.Error500InternalServerError("accept failed", err)
	}
	return authToken(key, exp, inv.Email, string(inv.Role), ""), nil
}

func normaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
