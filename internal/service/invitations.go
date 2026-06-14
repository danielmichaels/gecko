package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// InvitationsService exposes invitation management business logic.
type InvitationsService struct {
	*Service
}

// InvitationsCreateParams holds the caller-supplied fields for creating an invitation.
type InvitationsCreateParams struct {
	Email string
	Role  string
}

// InvitationsCreateResult holds the outcome of a successful Create call.
type InvitationsCreateResult struct {
	ExpiresAt time.Time
	Token     string
	Email     string
	Role      string
}

// Create issues an invitation for a teammate. Owner/manager only.
//
// Multi-tenant: an already-registered email is allowed — the invitee accepts while
// logged in to attach a membership. Only an email that is already a member of THIS
// tenant is rejected (ErrConflict). A stale expired invite for the same email is
// cleared first, while a still-live one collides on the partial unique index
// (ErrConflict). The invitation row and its email enqueue commit atomically; the
// raw token is also returned so the UI can reveal a copyable link as a fallback.
func (s *InvitationsService) Create(
	ctx context.Context,
	p *auth.Principal,
	params InvitationsCreateParams,
) (InvitationsCreateResult, error) {
	if err := ownerOrManager(p); err != nil {
		return InvitationsCreateResult{}, err
	}
	if err := requireCanGrant(p, params.Role); err != nil {
		return InvitationsCreateResult{}, err
	}
	email := normaliseEmail(params.Email)

	// Reject only if the email is already a member of THIS tenant; membership in
	// other tenants (or no account at all) is fine.
	if existing, err := s.DB.UserGetByEmail(ctx, email); err == nil {
		if _, mErr := s.DB.MembershipGetRole(ctx, store.MembershipGetRoleParams{
			UserID:   existing.ID,
			TenantID: p.TenantID,
		}); mErr == nil {
			return InvitationsCreateResult{}, msgErr(ErrConflict, "already a member of this tenant")
		} else if !errors.Is(mErr, pgx.ErrNoRows) {
			return InvitationsCreateResult{}, fmt.Errorf("create invitation: membership check: %w", mErr)
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return InvitationsCreateResult{}, fmt.Errorf("create invitation: lookup existing user: %w", err)
	}

	token, err := auth.GenerateToken()
	if err != nil {
		return InvitationsCreateResult{}, fmt.Errorf("create invitation: generate token: %w", err)
	}
	expiresAt := time.Now().Add(s.Conf.Auth.InviteTTL)

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return InvitationsCreateResult{}, fmt.Errorf("create invitation: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	if err := st.InvitationExpiredDelete(ctx, store.InvitationExpiredDeleteParams{
		TenantID: p.TenantID,
		Email:    email,
	}); err != nil {
		return InvitationsCreateResult{}, fmt.Errorf("create invitation: clear expired: %w", err)
	}

	if _, err := st.InvitationCreate(ctx, store.InvitationCreateParams{
		TenantID:  p.TenantID,
		Email:     email,
		Role:      store.UserRole(params.Role),
		TokenHash: auth.HashToken(token),
		InvitedBy: pgtype.Int4{Int32: p.UserID, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}); err != nil {
		if isUniqueViolation(err) {
			return InvitationsCreateResult{}, msgErr(
				ErrConflict,
				"an invitation for this email is already pending",
			)
		}
		return InvitationsCreateResult{}, fmt.Errorf("create invitation: insert: %w", err)
	}

	if s.emailer != nil {
		tenantName, _ := s.AuthService().TenantName(ctx, p.TenantID)
		msg := invitationEmail(email, tenantName, p.Email, s.Conf.AppConf.PublicBaseURL, token)
		if err := s.emailer.EnqueueEmail(ctx, tx, msg); err != nil {
			return InvitationsCreateResult{}, fmt.Errorf("create invitation: enqueue email: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return InvitationsCreateResult{}, fmt.Errorf("create invitation: commit: %w", err)
	}

	return InvitationsCreateResult{
		Token:     token,
		Email:     email,
		Role:      params.Role,
		ExpiresAt: expiresAt,
	}, nil
}

// List returns all invitations scoped to the caller's tenant. Any authenticated
// member may list; the query is tenant-scoped so no cross-tenant rows are returned.
func (s *InvitationsService) List(
	ctx context.Context,
	p *auth.Principal,
) ([]store.InvitationsListByTenantRow, error) {
	rows, err := s.DB.InvitationsListByTenant(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// Revoke deletes a pending invitation in the caller's tenant. Owner/manager only.
func (s *InvitationsService) Revoke(
	ctx context.Context,
	p *auth.Principal,
	uid string,
) error {
	if err := ownerOrManager(p); err != nil {
		return err
	}
	if _, err := s.DB.InvitationRevoke(ctx, store.InvitationRevokeParams{
		Uid:      uid,
		TenantID: p.TenantID,
	}); err != nil {
		return msgErr(ErrNotFound, "invitation not found")
	}
	return nil
}
