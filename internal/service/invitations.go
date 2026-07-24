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

type InvitationsService struct {
	*Service
}

type InvitationsCreateParams struct {
	Email string
	Role  string
}

type InvitationsCreateResult struct {
	ExpiresAt time.Time
	Token     string
	Email     string
	Role      string
}

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
			return InvitationsCreateResult{}, fmt.Errorf(
				"create invitation: enqueue email: %w",
				err,
			)
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
