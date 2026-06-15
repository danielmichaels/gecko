package service

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/mailer"
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

// Authenticate verifies email/password and returns the Principal on success.
// Returns ErrUnauthenticated for invalid or unknown credentials.
func (s *AuthService) Authenticate(
	ctx context.Context,
	email, password string,
) (*auth.Principal, error) {
	email = normaliseEmail(email)
	p, err := s.AuthProvider.Authenticate(ctx, auth.Credentials{
		Email:    email,
		Password: password,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: authenticate failed", ErrUnauthenticated)
	}
	return p, nil
}

// minPasswordLength is the floor for a user-chosen password. It mirrors the
// de-facto length used across signup/accept-invite flows; the browser enforces
// it client-side, and this is the server-side backstop.
const minPasswordLength = 8

// ChangePassword re-hashes and stores a new password for the caller after
// verifying their current one. An incorrect current password or a too-short new
// password returns ErrInvalidInput (the caller is authenticated; these are
// field-level validation failures, not authentication failures).
func (s *AuthService) ChangePassword(
	ctx context.Context,
	p *auth.Principal,
	current, next string,
) error {
	cred, err := s.DB.UserCredentialGetByUserID(ctx, p.UserID)
	if err != nil {
		return fmt.Errorf("change password: load credential: %w", err)
	}
	if err := auth.VerifyPassword(cred.PasswordHash, current); err != nil {
		return msgErr(ErrInvalidInput, "current password is incorrect")
	}
	if len(next) < minPasswordLength {
		return msgErr(ErrInvalidInput, "new password must be at least 8 characters")
	}
	hash, err := auth.HashPassword(next, s.Conf.Auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("change password: hash: %w", err)
	}
	if err := s.DB.UserCredentialUpsert(ctx, store.UserCredentialUpsertParams{
		UserID:       p.UserID,
		PasswordHash: hash,
	}); err != nil {
		return fmt.Errorf("change password: upsert: %w", err)
	}
	return nil
}

// Login verifies credentials and mints an API key for CLI/programmatic use.
// Returns ErrUnauthenticated for invalid credentials.
func (s *AuthService) Login(ctx context.Context, email, password string) (LoginResult, error) {
	p, err := s.Authenticate(ctx, email, password)
	if err != nil {
		return LoginResult{}, err
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

// provisioned carries the identifiers of a freshly provisioned user/tenant,
// shared by the signup and accept-invite flows to build their distinct results.
type provisioned struct {
	tenantUID string
	email     string
	role      store.UserRole
	userID    int32
	tenantID  int32
}

// withTxStep runs variant-specific work inside a provisioning transaction (e.g.
// minting an API key atomically). The web variants pass nil.
type withTxStep func(st *store.Queries, tenantID, userID int32) error

// createTenantOwner runs the shared signup transaction: reject duplicate emails,
// hash the password, create the tenant, provision the owner, store the credential,
// run mintStep (if any) in-tx, and enqueue the welcome email. The only thing the
// two public signup methods do differently is mintStep and how they shape the
// result, keeping tenant creation identical across the API and browser paths.
func (s *AuthService) createTenantOwner(
	ctx context.Context,
	params SignupParams,
	mintStep withTxStep,
) (provisioned, error) {
	email := normaliseEmail(params.Email)
	if _, err := s.DB.UserGetByEmail(ctx, email); err == nil {
		return provisioned{}, fmt.Errorf("%w: email already registered", ErrConflict)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return provisioned{}, fmt.Errorf("signup: lookup: %w", err)
	}
	hash, err := auth.HashPassword(params.Password, s.Conf.Auth.BcryptCost)
	if err != nil {
		return provisioned{}, fmt.Errorf("signup: hash password: %w", err)
	}
	tenantName := strings.TrimSpace(params.TenantName)
	if tenantName == "" {
		tenantName = email
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return provisioned{}, fmt.Errorf("signup: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	tenant, err := st.TenantCreate(ctx, tenantName)
	if err != nil {
		return provisioned{}, fmt.Errorf("signup: create tenant: %w", err)
	}
	user, err := st.UserProvisionIdentity(ctx, store.UserProvisionIdentityParams{
		Email: email,
		Name:  pgtype.Text{String: params.Name, Valid: params.Name != ""},
	})
	if err != nil {
		if isUniqueViolation(err) {
			return provisioned{}, fmt.Errorf("%w: email already registered", ErrConflict)
		}
		return provisioned{}, fmt.Errorf("signup: provision user: %w", err)
	}
	if err := st.UserCredentialUpsert(ctx, store.UserCredentialUpsertParams{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		return provisioned{}, fmt.Errorf("signup: credential upsert: %w", err)
	}
	if _, err := st.MembershipCreate(ctx, store.MembershipCreateParams{
		UserID:   user.ID,
		TenantID: tenant.ID,
		Role:     store.UserRoleOwner,
	}); err != nil {
		return provisioned{}, fmt.Errorf("signup: create membership: %w", err)
	}
	if mintStep != nil {
		if err := mintStep(st, tenant.ID, user.ID); err != nil {
			return provisioned{}, err
		}
	}
	if s.emailer != nil {
		welcome := welcomeEmail(email, tenant.Name, s.Conf.AppConf.PublicBaseURL)
		if err := s.emailer.EnqueueEmail(ctx, tx, welcome); err != nil {
			return provisioned{}, fmt.Errorf("signup: enqueue welcome email: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return provisioned{}, fmt.Errorf("signup: commit: %w", err)
	}
	return provisioned{
		userID:    user.ID,
		tenantID:  tenant.ID,
		tenantUID: tenant.Uid,
		email:     email,
		role:      store.UserRoleOwner,
	}, nil
}

// Signup creates a new tenant and its first owner, then mints a key.
// Duplicate email raises ErrConflict. SignupEnabled is NOT checked here;
// that policy gate stays in the handler to preserve the exact 403 message.
func (s *AuthService) Signup(ctx context.Context, params SignupParams) (SignupResult, error) {
	var key auth.APIKey
	var exp pgtype.Timestamptz
	p, err := s.createTenantOwner(
		ctx,
		params,
		func(st *store.Queries, tenantID, userID int32) error {
			k, _, e, mErr := s.mintAPIKey(ctx, st, tenantID, userID, "signup")
			if mErr != nil {
				return fmt.Errorf("signup: mint key: %w", mErr)
			}
			key, exp = k, e
			return nil
		},
	)
	if err != nil {
		return SignupResult{}, err
	}
	return SignupResult{
		RawKey:    key.Raw,
		ExpiresAt: exp,
		Email:     p.email,
		Role:      string(p.role),
		TenantUID: p.tenantUID,
	}, nil
}

// SignupWeb creates a new tenant and its first owner without minting an API key.
// Used by the browser flow, which mints a session instead. Duplicate email raises
// ErrConflict. SignupEnabled is NOT checked here; that policy gate stays in the
// handler.
func (s *AuthService) SignupWeb(ctx context.Context, params SignupParams) (*auth.Principal, error) {
	p, err := s.createTenantOwner(ctx, params, nil)
	if err != nil {
		return nil, err
	}
	return &auth.Principal{
		UserID:   p.userID,
		TenantID: p.tenantID,
		Email:    p.email,
		Role:     string(p.role),
	}, nil
}

// AcceptInviteParams holds the caller-supplied fields for accepting an invitation.
type AcceptInviteParams struct {
	Token    string
	Password string
	Name     string
}

// consumeInvitation runs the new-user accept-invite transaction: resolve the
// token, create the identity, store the credential, attach a membership with the
// invited role, mark the invitation accepted, and run mintStep (if any) in-tx. It
// is only for invitees who do NOT yet have an account; an invite addressed to an
// existing identity must be accepted while logged in (AttachInviteWeb), so a link
// alone never attaches a tenant to someone else's account.
// Invalid/expired token → ErrNotFound. Existing account → ErrConflict (login).
func (s *AuthService) consumeInvitation(
	ctx context.Context,
	params AcceptInviteParams,
	mintStep withTxStep,
) (provisioned, error) {
	inv, err := s.DB.InvitationGetByTokenHash(ctx, auth.HashToken(params.Token))
	if err != nil {
		// Deliberately opaque: expired and invalid tokens both return not-found
		// so callers cannot distinguish the two cases.
		return provisioned{}, fmt.Errorf("%w: invalid or expired invitation", ErrNotFound)
	}
	// An invite to an already-registered email must be accepted while authenticated
	// as that identity; reject the password-based path here.
	if _, err := s.DB.UserGetByEmail(ctx, inv.Email); err == nil {
		return provisioned{}, msgErr(
			ErrConflict,
			"an account already exists for this email — log in to accept the invitation",
		)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return provisioned{}, fmt.Errorf("accept invite: lookup user: %w", err)
	}

	if len(params.Password) < minPasswordLength {
		return provisioned{}, msgErr(ErrInvalidInput, "password must be at least 8 characters")
	}
	hash, err := auth.HashPassword(params.Password, s.Conf.Auth.BcryptCost)
	if err != nil {
		return provisioned{}, fmt.Errorf("accept invite: hash password: %w", err)
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return provisioned{}, fmt.Errorf("accept invite: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	user, err := st.UserProvisionIdentity(ctx, store.UserProvisionIdentityParams{
		Email: inv.Email,
		Name:  pgtype.Text{String: params.Name, Valid: params.Name != ""},
	})
	if err != nil {
		if isUniqueViolation(err) {
			return provisioned{}, msgErr(
				ErrConflict,
				"an account already exists for this email — log in to accept the invitation",
			)
		}
		return provisioned{}, fmt.Errorf("accept invite: provision user: %w", err)
	}
	if err := st.UserCredentialUpsert(ctx, store.UserCredentialUpsertParams{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		return provisioned{}, fmt.Errorf("accept invite: credential upsert: %w", err)
	}
	if _, err := st.MembershipCreate(ctx, store.MembershipCreateParams{
		UserID:   user.ID,
		TenantID: inv.TenantID,
		Role:     inv.Role,
	}); err != nil {
		return provisioned{}, fmt.Errorf("accept invite: create membership: %w", err)
	}
	if err := st.InvitationMarkAccepted(ctx, inv.ID); err != nil {
		return provisioned{}, fmt.Errorf("accept invite: mark accepted: %w", err)
	}
	if mintStep != nil {
		if err := mintStep(st, inv.TenantID, user.ID); err != nil {
			return provisioned{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return provisioned{}, fmt.Errorf("accept invite: commit: %w", err)
	}
	return provisioned{
		userID:   user.ID,
		tenantID: inv.TenantID,
		email:    inv.Email,
		role:     inv.Role,
	}, nil
}

// attachInvite validates an invitation token against the authenticated caller's
// own email, creates the membership with the invited role, marks the invite
// accepted, and runs mintStep (if any) in-tx. It is the shared core of the web and
// API "existing account joins another tenant" flows. A link alone can never attach
// a tenant to a different identity. Invalid/expired token → ErrNotFound; an invite
// for a different identity → ErrForbidden; already a member → ErrConflict.
func (s *AuthService) attachInvite(
	ctx context.Context,
	p *auth.Principal,
	token string,
	mintStep withTxStep,
) (tenantID int32, role store.UserRole, err error) {
	inv, err := s.DB.InvitationGetByTokenHash(ctx, auth.HashToken(token))
	if err != nil {
		// The live invite is gone: unknown token, expired, or already claimed. If
		// the caller is the invitee and is already a member of the invited tenant,
		// surface that as a conflict rather than a misleading not-found.
		if used, lookupErr := s.DB.InvitationGetByTokenHashIncludingUsed(ctx, auth.HashToken(token)); lookupErr == nil &&
			normaliseEmail(used.Email) == normaliseEmail(p.Email) {
			if _, mErr := s.DB.MembershipGetRole(ctx, store.MembershipGetRoleParams{
				UserID:   p.UserID,
				TenantID: used.TenantID,
			}); mErr == nil {
				return 0, "", msgErr(ErrConflict, "you are already a member of this tenant")
			}
		}
		return 0, "", fmt.Errorf("%w: invalid or expired invitation", ErrNotFound)
	}
	if normaliseEmail(inv.Email) != normaliseEmail(p.Email) {
		return 0, "", msgErr(ErrForbidden, "this invitation was sent to a different account")
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, "", fmt.Errorf("attach invite: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	if _, err := st.MembershipCreate(ctx, store.MembershipCreateParams{
		UserID:   p.UserID,
		TenantID: inv.TenantID,
		Role:     inv.Role,
	}); err != nil {
		if isUniqueViolation(err) {
			return 0, "", msgErr(ErrConflict, "you are already a member of this tenant")
		}
		return 0, "", fmt.Errorf("attach invite: create membership: %w", err)
	}
	if err := st.InvitationMarkAccepted(ctx, inv.ID); err != nil {
		return 0, "", fmt.Errorf("attach invite: mark accepted: %w", err)
	}
	if mintStep != nil {
		if err := mintStep(st, inv.TenantID, p.UserID); err != nil {
			return 0, "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, "", fmt.Errorf("attach invite: commit: %w", err)
	}
	return inv.TenantID, inv.Role, nil
}

// AttachInviteWeb attaches the authenticated caller to the tenant named by an
// invitation token (for invitees who already have an account) and returns the
// tenant id so the caller can switch the active session to it.
func (s *AuthService) AttachInviteWeb(
	ctx context.Context,
	p *auth.Principal,
	token string,
) (int32, error) {
	tenantID, _, err := s.attachInvite(ctx, p, token, nil)
	return tenantID, err
}

// AttachInvite is the API counterpart of AttachInviteWeb: it attaches the
// authenticated caller to the invited tenant and mints an API key scoped to that
// tenant, returning it. This is how an existing API user obtains their first key
// for a newly joined tenant (keys are per-tenant).
func (s *AuthService) AttachInvite(
	ctx context.Context,
	p *auth.Principal,
	token string,
) (AcceptInviteResult, error) {
	var key auth.APIKey
	var exp pgtype.Timestamptz
	_, role, err := s.attachInvite(
		ctx,
		p,
		token,
		func(st *store.Queries, tenantID, userID int32) error {
			k, _, e, mErr := s.mintAPIKey(ctx, st, tenantID, userID, "invite-attach")
			if mErr != nil {
				return fmt.Errorf("attach invite: mint key: %w", mErr)
			}
			key, exp = k, e
			return nil
		},
	)
	if err != nil {
		return AcceptInviteResult{}, err
	}
	return AcceptInviteResult{
		RawKey:    key.Raw,
		ExpiresAt: exp,
		Email:     p.Email,
		Role:      string(role),
	}, nil
}

// AcceptInvite consumes an invitation token, creating the user with the
// invited role in the inviting tenant, and mints a key.
// Invalid/expired token → ErrNotFound. Duplicate email → ErrConflict.
func (s *AuthService) AcceptInvite(
	ctx context.Context,
	params AcceptInviteParams,
) (AcceptInviteResult, error) {
	var key auth.APIKey
	var exp pgtype.Timestamptz
	p, err := s.consumeInvitation(
		ctx,
		params,
		func(st *store.Queries, tenantID, userID int32) error {
			k, _, e, mErr := s.mintAPIKey(ctx, st, tenantID, userID, "invite-accept")
			if mErr != nil {
				return fmt.Errorf("accept invite: mint key: %w", mErr)
			}
			key, exp = k, e
			return nil
		},
	)
	if err != nil {
		return AcceptInviteResult{}, err
	}
	return AcceptInviteResult{
		RawKey:    key.Raw,
		ExpiresAt: exp,
		Email:     p.email,
		Role:      string(p.role),
	}, nil
}

// AcceptInviteWeb provisions a user from an invitation token without minting an
// API key. Used by the browser flow; the caller then mints a session instead.
// Invalid/expired token → ErrNotFound. Duplicate email → ErrConflict.
func (s *AuthService) AcceptInviteWeb(
	ctx context.Context,
	params AcceptInviteParams,
) (*auth.Principal, error) {
	p, err := s.consumeInvitation(ctx, params, nil)
	if err != nil {
		return nil, err
	}
	return &auth.Principal{
		UserID:   p.userID,
		TenantID: p.tenantID,
		Email:    p.email,
		Role:     string(p.role),
	}, nil
}

// InviteContext holds the display fields for the accept-invitation page.
type InviteContext struct {
	InviteeEmail string
	InviterEmail string
	Role         string
	Expiry       string
	TenantName   string
	// ExistingUser is true when the invitee email already has an account, so the
	// UI directs them to log in and attach the membership rather than set a password.
	ExistingUser bool
}

// InviteContextFromToken looks up the invitation and returns display fields.
// Returns ErrNotFound for unknown, expired, or already-accepted tokens.
func (s *AuthService) InviteContextFromToken(
	ctx context.Context,
	token string,
) (InviteContext, error) {
	inv, err := s.DB.InvitationGetByTokenHash(ctx, auth.HashToken(token))
	if err != nil {
		return InviteContext{}, fmt.Errorf("%w: invalid or expired invitation", ErrNotFound)
	}
	ic := InviteContext{
		InviteeEmail: inv.Email,
		Role:         string(inv.Role),
		Expiry:       inv.ExpiresAt.Time.Format("2006-01-02 15:04 UTC"),
	}
	if _, err := s.DB.UserGetByEmail(ctx, normaliseEmail(inv.Email)); err == nil {
		ic.ExistingUser = true
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return InviteContext{}, fmt.Errorf("invite context: lookup user: %w", err)
	}
	if tenant, err := s.DB.TenantGetByID(ctx, inv.TenantID); err == nil {
		ic.TenantName = tenant.Name
	}
	if inv.InvitedBy.Valid {
		if inviter, err := s.DB.UserGetByID(ctx, inv.InvitedBy.Int32); err == nil {
			ic.InviterEmail = inviter.Email
		}
	}
	return ic, nil
}

// TenantName returns the display name for a tenant. Best-effort: returns an
// empty string when the tenant is not found rather than propagating an error.
func (s *AuthService) TenantName(ctx context.Context, tenantID int32) (string, error) {
	tenant, err := s.DB.TenantGetByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("%w: tenant not found", ErrNotFound)
		}
		return "", fmt.Errorf("tenant name: %w", err)
	}
	return tenant.Name, nil
}

// MembershipSummary is one tenant a user belongs to, for the UI tenant switcher.
// Active marks the membership matching the caller's current active tenant.
type MembershipSummary struct {
	TenantUID  string
	TenantName string
	Role       string
	Active     bool
}

// ListMemberships returns the tenants the caller belongs to, flagging the one that
// is currently active. Drives the topbar tenant switcher.
func (s *AuthService) ListMemberships(
	ctx context.Context,
	p *auth.Principal,
) ([]MembershipSummary, error) {
	rows, err := s.DB.MembershipsListForUser(ctx, p.UserID)
	if err != nil {
		return nil, fmt.Errorf("list memberships: %w", err)
	}
	out := make([]MembershipSummary, len(rows))
	for i, r := range rows {
		out[i] = MembershipSummary{
			TenantUID:  r.TenantUid,
			TenantName: r.TenantName,
			Role:       string(r.Role),
			Active:     r.TenantID == p.TenantID,
		}
	}
	return out, nil
}

// Workspace identifies a newly created tenant.
type Workspace struct {
	TenantUID  string
	TenantName string
	TenantID   int32
}

// CreateWorkspace creates a new tenant owned by the authenticated caller and
// attaches them as its owner. It is the in-app path for an existing account to
// spin up an additional workspace (public signup only creates brand-new
// identities). The caller switches the active session to it separately.
func (s *AuthService) CreateWorkspace(
	ctx context.Context,
	p *auth.Principal,
	name string,
) (Workspace, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Workspace{}, msgErr(ErrInvalidInput, "workspace name is required")
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Workspace{}, fmt.Errorf("create workspace: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	tenant, err := st.TenantCreate(ctx, name)
	if err != nil {
		return Workspace{}, fmt.Errorf("create workspace: create tenant: %w", err)
	}
	if _, err := st.MembershipCreate(ctx, store.MembershipCreateParams{
		UserID:   p.UserID,
		TenantID: tenant.ID,
		Role:     store.UserRoleOwner,
	}); err != nil {
		return Workspace{}, fmt.Errorf("create workspace: create membership: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Workspace{}, fmt.Errorf("create workspace: commit: %w", err)
	}
	return Workspace{TenantID: tenant.ID, TenantUID: tenant.Uid, TenantName: tenant.Name}, nil
}

// SwitchTenant points the caller's current session at a different tenant they
// belong to. It validates membership in the target tenant (ErrForbidden / ErrNotFound
// otherwise) and updates the session row's active tenant in place, so the cookie and
// CSRF token stay valid. rawSessionToken is the caller's current session token.
func (s *AuthService) SwitchTenant(
	ctx context.Context,
	p *auth.Principal,
	tenantUID, rawSessionToken string,
) error {
	tenant, err := s.DB.TenantGetByUID(ctx, tenantUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return msgErr(ErrNotFound, "tenant not found")
		}
		return fmt.Errorf("switch tenant: lookup tenant: %w", err)
	}
	if _, err := s.DB.MembershipGetRole(ctx, store.MembershipGetRoleParams{
		UserID:   p.UserID,
		TenantID: tenant.ID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return msgErr(ErrForbidden, "you are not a member of that tenant")
		}
		return fmt.Errorf("switch tenant: membership check: %w", err)
	}
	if err := s.DB.SessionUpdateTenant(ctx, store.SessionUpdateTenantParams{
		TokenHash: auth.HashToken(rawSessionToken),
		TenantID:  tenant.ID,
	}); err != nil {
		return fmt.Errorf("switch tenant: update session: %w", err)
	}
	return nil
}

// SetSessionTenant points the given session at tenantID without re-checking
// membership. Callers that have just established membership (e.g. accepting an
// invite) use this to land the user in the new tenant; untrusted switches must go
// through SwitchTenant, which validates membership first.
func (s *AuthService) SetSessionTenant(
	ctx context.Context,
	rawSessionToken string,
	tenantID int32,
) error {
	if err := s.DB.SessionUpdateTenant(ctx, store.SessionUpdateTenantParams{
		TokenHash: auth.HashToken(rawSessionToken),
		TenantID:  tenantID,
	}); err != nil {
		return fmt.Errorf("set session tenant: %w", err)
	}
	return nil
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
func (s *AuthService) ResolveSession(
	ctx context.Context,
	rawToken string,
) (*auth.Principal, error) {
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

// RequestPasswordReset issues a password-reset token for the address and queues
// the reset email. It never reveals whether the address is registered: an unknown
// email returns nil without creating a token or enqueuing mail. The token row and
// the email job are written in one transaction so a link is only ever sent for a
// token that exists. baseURL is the public origin used to build the reset link.
func (s *AuthService) RequestPasswordReset(ctx context.Context, email, baseURL string) error {
	email = normaliseEmail(email)
	user, err := s.DB.UserGetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("request password reset: lookup: %w", err)
	}

	rawToken, err := auth.GenerateToken()
	if err != nil {
		return fmt.Errorf("request password reset: generate token: %w", err)
	}
	expiresAt := time.Now().Add(s.Conf.Auth.ResetTTL)

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("request password reset: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	if _, err := st.PasswordResetTokenCreate(ctx, store.PasswordResetTokenCreateParams{
		UserID:    user.ID,
		TokenHash: auth.HashToken(rawToken),
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}); err != nil {
		return fmt.Errorf("request password reset: create token: %w", err)
	}

	if s.emailer != nil {
		if err := s.emailer.EnqueueEmail(ctx, tx, passwordResetEmail(user.Email, baseURL, rawToken)); err != nil {
			return fmt.Errorf("request password reset: enqueue email: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("request password reset: commit: %w", err)
	}
	return nil
}

// ResetPassword consumes a reset token, sets the new password, and revokes every
// session for the user so a forgotten or compromised credential cannot survive on
// an existing session. Invalid, expired, or already-used tokens return ErrNotFound;
// a too-short new password returns ErrInvalidInput.
func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	tok, err := s.DB.PasswordResetTokenGetByHash(ctx, auth.HashToken(token))
	if err != nil {
		return fmt.Errorf("%w: invalid or expired reset token", ErrNotFound)
	}
	if len(newPassword) < minPasswordLength {
		return msgErr(ErrInvalidInput, "new password must be at least 8 characters")
	}
	hash, err := auth.HashPassword(newPassword, s.Conf.Auth.BcryptCost)
	if err != nil {
		return fmt.Errorf("reset password: hash: %w", err)
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("reset password: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	if err := st.UserCredentialUpsert(ctx, store.UserCredentialUpsertParams{
		UserID:       tok.UserID,
		PasswordHash: hash,
	}); err != nil {
		return fmt.Errorf("reset password: credential upsert: %w", err)
	}
	if err := st.PasswordResetTokenMarkUsed(ctx, tok.ID); err != nil {
		return fmt.Errorf("reset password: mark used: %w", err)
	}
	if err := st.SessionRevokeAllForUser(ctx, tok.UserID); err != nil {
		return fmt.Errorf("reset password: revoke sessions: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("reset password: commit: %w", err)
	}
	return nil
}

// welcomeEmail renders the post-signup acknowledgement. Any link uses the trusted
// PublicBaseURL (config), never request headers — the message is emailed to the
// new owner, so a request-derived origin would be injectable.
func welcomeEmail(to, tenantName, baseURL string) mailer.Message {
	link := baseURL + "/app/domains"
	safeTenant := html.EscapeString(tenantName)
	safeLink := html.EscapeString(link)
	return mailer.Message{
		To:      to,
		Subject: "Welcome to gecko",
		HTML: "<p>Welcome to gecko — your workspace <b>" + safeTenant + "</b> is ready.</p>" +
			"<p>Add your first domain and we'll start watching its DNS for misconfigurations.</p>" +
			"<p><a href=\"" + safeLink + "\">Open your dashboard</a></p>",
		Text: "Welcome to gecko — your workspace " + tenantName + " is ready.\n\n" +
			"Add your first domain and we'll start watching its DNS for misconfigurations.\n" +
			"Open your dashboard: " + link,
	}
}

// passwordResetEmail renders the reset message. With no mailer-side templating in
// the codebase yet, the body is built here so the worker stays a thin transport.
func passwordResetEmail(to, baseURL, rawToken string) mailer.Message {
	link := baseURL + "/app/reset-password?token=" + rawToken
	safeLink := html.EscapeString(link)
	return mailer.Message{
		To:      to,
		Subject: "Reset your gecko password",
		HTML: "<p>We received a request to reset your gecko password.</p>" +
			"<p><a href=\"" + safeLink + "\">Reset your password</a></p>" +
			"<p>If you did not request this, you can ignore this email.</p>",
		Text: "Reset your gecko password using this link:\n" + link +
			"\n\nIf you did not request this, you can ignore this email.",
	}
}

// invitationEmail renders the team-invitation message. The accept link uses the
// trusted PublicBaseURL (config), never request headers, since the message is
// emailed — a request-derived origin would be injectable (link poisoning).
func invitationEmail(to, tenantName, inviterEmail, baseURL, rawToken string) mailer.Message {
	link := baseURL + "/app/invite?token=" + rawToken
	intro := "You have been invited to join the workspace " + tenantName + " on gecko."
	safeIntro := "You have been invited to join the workspace " +
		html.EscapeString(tenantName) + " on gecko."
	if inviterEmail != "" {
		intro = inviterEmail + " invited you to join the workspace " + tenantName + " on gecko."
		safeIntro = html.EscapeString(inviterEmail) + " invited you to join the workspace " +
			html.EscapeString(tenantName) + " on gecko."
	}
	safeLink := html.EscapeString(link)
	return mailer.Message{
		To:      to,
		Subject: "You've been invited to " + tenantName + " on gecko",
		HTML: "<p>" + safeIntro + "</p>" +
			"<p><a href=\"" + safeLink + "\">Accept your invitation</a></p>" +
			"<p>If you weren't expecting this, you can ignore this email.</p>",
		Text: intro + "\n\nAccept your invitation: " + link +
			"\n\nIf you weren't expecting this, you can ignore this email.",
	}
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
