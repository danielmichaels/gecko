package server

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/service"
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

func authOutputFromResult(
	rawKey string,
	exp pgtype.Timestamptz,
	email, role, tenantUID string,
) *authOutput {
	out := &authOutput{}
	out.Body.APIKey = rawKey
	out.Body.Email = email
	out.Body.Role = role
	out.Body.TenantUID = tenantUID
	if exp.Valid {
		t := exp.Time
		out.Body.ExpiresAt = &t
	}
	return out
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
	result, err := app.Svc.AuthService().Signup(ctx, service.SignupParams{
		Email:      i.Body.Email,
		Password:   i.Body.Password,
		Name:       i.Body.Name,
		TenantName: i.Body.TenantName,
	})
	if err != nil {
		if errors.Is(err, service.ErrConflict) {
			return nil, huma.Error409Conflict("email already registered")
		}
		return nil, huma.Error500InternalServerError("signup failed", err)
	}
	return authOutputFromResult(
		result.RawKey,
		result.ExpiresAt,
		result.Email,
		result.Role,
		result.TenantUID,
	), nil
}

type LoginInput struct {
	Body struct {
		Email    string `json:"email"    required:"true" format:"email"`
		Password string `json:"password" required:"true"`
	}
}

// handleLogin verifies credentials and mints an API key for programmatic/CLI use.
func (app *Server) handleLogin(ctx context.Context, i *LoginInput) (*authOutput, error) {
	result, err := app.Svc.AuthService().Login(ctx, i.Body.Email, i.Body.Password)
	if err != nil {
		if errors.Is(err, service.ErrUnauthenticated) {
			return nil, huma.Error401Unauthorized("invalid credentials")
		}
		return nil, huma.Error500InternalServerError("login failed", err)
	}
	return authOutputFromResult(result.RawKey, result.ExpiresAt, result.Email, result.Role, ""), nil
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
	if err := app.Svc.AuthService().Logout(ctx, p, uid); err != nil {
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

type ChangePasswordInput struct {
	Body struct {
		CurrentPassword string `json:"current_password" required:"true"`
		NewPassword     string `json:"new_password"     required:"true" minLength:"8"`
	}
}

// handleChangePassword verifies the caller's current password and sets a new one.
func (app *Server) handleChangePassword(
	ctx context.Context,
	i *ChangePasswordInput,
) (*struct{}, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	if err := app.Svc.AuthService().ChangePassword(ctx, p, i.Body.CurrentPassword, i.Body.NewPassword); err != nil {
		if errors.Is(err, service.ErrInvalidInput) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		return nil, huma.Error500InternalServerError("failed to change password", err)
	}
	return &struct{}{}, nil
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
	result, err := app.Svc.AuthService().AcceptInvite(ctx, service.AcceptInviteParams{
		Token:    i.Body.Token,
		Password: i.Body.Password,
		Name:     i.Body.Name,
	})
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return nil, huma.Error400BadRequest("invalid or expired invitation")
		}
		if errors.Is(err, service.ErrInvalidInput) {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if errors.Is(err, service.ErrConflict) {
			return nil, huma.Error409Conflict(err.Error())
		}
		return nil, huma.Error500InternalServerError("accept failed", err)
	}
	return authOutputFromResult(result.RawKey, result.ExpiresAt, result.Email, result.Role, ""), nil
}

// AttachInviteInput is the body for an authenticated existing account joining the
// tenant named by an invitation token.
type AttachInviteInput struct {
	Body struct {
		Token string `json:"token" required:"true" doc:"Invitation token addressed to the caller's own email."`
	}
}

// handleAttachInvite attaches the authenticated caller to the invited tenant and
// returns a fresh API key scoped to that tenant. The invite must be addressed to
// the caller's own email; otherwise it is refused.
func (app *Server) handleAttachInvite(
	ctx context.Context,
	i *AttachInviteInput,
) (*authOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	result, err := app.Svc.AuthService().AttachInvite(ctx, p, i.Body.Token)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrNotFound):
			return nil, huma.Error400BadRequest("invalid or expired invitation")
		case errors.Is(err, service.ErrForbidden):
			return nil, huma.Error403Forbidden(err.Error())
		case errors.Is(err, service.ErrConflict):
			return nil, huma.Error409Conflict(err.Error())
		default:
			return nil, huma.Error500InternalServerError("attach failed", err)
		}
	}
	return authOutputFromResult(result.RawKey, result.ExpiresAt, result.Email, result.Role, ""), nil
}
