package server

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/service"
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
func (app *Server) handleInviteCreate(
	ctx context.Context,
	i *CreateInviteInput,
) (*CreateInviteOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	result, err := app.Svc.InvitationsService().Create(ctx, p, service.InvitationsCreateParams{
		Email: i.Body.Email,
		Role:  i.Body.Role,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			return nil, huma.Error403Forbidden(err.Error())
		case errors.Is(err, service.ErrConflict):
			return nil, huma.Error409Conflict(err.Error())
		default:
			return nil, huma.Error500InternalServerError("failed to create invitation", err)
		}
	}
	out := &CreateInviteOutput{}
	out.Body.Token = result.Token
	out.Body.Email = result.Email
	out.Body.Role = result.Role
	out.Body.ExpiresAt = result.ExpiresAt
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
	rows, err := app.Svc.InvitationsService().List(ctx, p)
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
	if err := app.Svc.InvitationsService().Revoke(ctx, p, i.UID); err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			return nil, huma.Error403Forbidden(err.Error())
		case errors.Is(err, service.ErrNotFound):
			return nil, huma.Error404NotFound(err.Error())
		default:
			return nil, huma.Error500InternalServerError("failed to revoke invitation", err)
		}
	}
	return &struct{}{}, nil
}
