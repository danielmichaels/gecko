package server

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type CreateInviteInput struct {
	Body struct {
		Email string `json:"email" required:"true" format:"email"`
		Role  string `json:"role"  required:"true" enum:"owner,manager,viewer" doc:"Role the invitee will hold; superadmin cannot be invited."`
	}
}

type CreateInviteOutput struct {
	Body struct {
		ExpiresAt time.Time `json:"expires_at"`
		Token     string    `json:"token" doc:"Invitation token — shown once. Deliver it to the invitee (email delivery is out of scope)."`
		Email     string    `json:"email"`
		Role      string    `json:"role"`
	}
}

// handleInviteCreate issues an invitation for a new teammate. Owner/manager only.
// Single-tenant emails: an already-registered email is rejected 409 before a token
// is minted; a stale expired invite for the same email is cleared first, while a
// still-live one collides on the partial unique index (409).
func (app *Server) handleInviteCreate(
	ctx context.Context,
	i *CreateInviteInput,
) (*CreateInviteOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	if err := ownerOrManager(p); err != nil {
		return nil, err
	}
	if err := requireCanGrant(p, i.Body.Role); err != nil {
		return nil, err
	}
	email := normaliseEmail(i.Body.Email)

	if _, err := app.Db.UserGetByEmail(ctx, email); err == nil {
		return nil, huma.Error409Conflict("email already registered")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, huma.Error500InternalServerError("failed to create invitation", err)
	}

	if err := app.Db.InvitationExpiredDelete(ctx, store.InvitationExpiredDeleteParams{
		TenantID: p.TenantID,
		Email:    email,
	}); err != nil {
		return nil, huma.Error500InternalServerError("failed to create invitation", err)
	}

	token, err := auth.GenerateToken()
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to create invitation", err)
	}
	expiresAt := time.Now().Add(app.Conf.Auth.InviteTTL)

	if _, err := app.Db.InvitationCreate(ctx, store.InvitationCreateParams{
		TenantID:  p.TenantID,
		Email:     email,
		Role:      store.UserRole(i.Body.Role),
		TokenHash: auth.HashToken(token),
		InvitedBy: pgtype.Int4{Int32: p.UserID, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}); err != nil {
		if isUniqueViolation(err) {
			return nil, huma.Error409Conflict("an invitation for this email is already pending")
		}
		return nil, huma.Error500InternalServerError("failed to create invitation", err)
	}

	out := &CreateInviteOutput{}
	out.Body.Token = token
	out.Body.Email = email
	out.Body.Role = i.Body.Role
	out.Body.ExpiresAt = expiresAt
	return out, nil
}

type inviteView struct {
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	UID        string     `json:"uid"`
	Email      string     `json:"email"`
	Role       string     `json:"role"`
}

type ListInvitesOutput struct {
	Body struct {
		Invitations []inviteView `json:"invitations"`
	}
}

// handleInviteList lists the tenant's invitations.
func (app *Server) handleInviteList(ctx context.Context, _ *struct{}) (*ListInvitesOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := app.Db.InvitationsListByTenant(ctx, p.TenantID)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to list invitations", err)
	}
	out := &ListInvitesOutput{}
	out.Body.Invitations = make([]inviteView, 0, len(rows))
	for _, r := range rows {
		out.Body.Invitations = append(out.Body.Invitations, inviteView{
			UID:        r.Uid,
			Email:      r.Email,
			Role:       string(r.Role),
			ExpiresAt:  tsPtr(r.ExpiresAt),
			AcceptedAt: tsPtr(r.AcceptedAt),
			CreatedAt:  tsPtr(r.CreatedAt),
		})
	}
	return out, nil
}

type InviteRevokeInput struct {
	UID string `path:"uid" example:"invite_00000001"`
}

// handleInviteRevoke deletes a pending invitation in the caller's tenant.
func (app *Server) handleInviteRevoke(
	ctx context.Context,
	i *InviteRevokeInput,
) (*struct{}, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	if err := ownerOrManager(p); err != nil {
		return nil, err
	}
	if _, err := app.Db.InvitationRevoke(ctx, store.InvitationRevokeParams{
		Uid:      i.UID,
		TenantID: p.TenantID,
	}); err != nil {
		return nil, huma.Error404NotFound("invitation not found")
	}
	return &struct{}{}, nil
}
