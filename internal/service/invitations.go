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

// Create issues an invitation for a new teammate. Owner/manager only.
//
// Single-tenant emails: an already-registered email is rejected (ErrConflict)
// before a token is minted; a stale expired invite for the same email is cleared
// first, while a still-live one collides on the partial unique index (ErrConflict).
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

	if _, err := s.DB.UserGetByEmail(ctx, email); err == nil {
		return InvitationsCreateResult{}, msgErr(ErrConflict, "email already registered")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return InvitationsCreateResult{}, fmt.Errorf("create invitation: lookup existing user: %w", err)
	}

	if err := s.DB.InvitationExpiredDelete(ctx, store.InvitationExpiredDeleteParams{
		TenantID: p.TenantID,
		Email:    email,
	}); err != nil {
		return InvitationsCreateResult{}, fmt.Errorf("create invitation: clear expired: %w", err)
	}

	token, err := auth.GenerateToken()
	if err != nil {
		return InvitationsCreateResult{}, fmt.Errorf("create invitation: generate token: %w", err)
	}
	expiresAt := time.Now().Add(s.Conf.Auth.InviteTTL)

	if _, err := s.DB.InvitationCreate(ctx, store.InvitationCreateParams{
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
