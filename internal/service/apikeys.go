package service

import (
	"context"
	"fmt"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

type APIKeysService struct {
	*Service
}

type APIKeysCreateResult struct {
	ExpiresAt pgtype.Timestamptz
	UID       string
	Raw       string
	Prefix    string
}

func (s *APIKeysService) Create(
	ctx context.Context,
	p *auth.Principal,
	name string,
) (APIKeysCreateResult, error) {
	if err := ownerOrManager(p); err != nil {
		return APIKeysCreateResult{}, err
	}
	key, uid, exp, err := s.AuthService().mintAPIKey(ctx, s.DB, p.TenantID, p.UserID, name)
	if err != nil {
		return APIKeysCreateResult{}, fmt.Errorf("create api key: mint: %w", err)
	}
	return APIKeysCreateResult{
		UID:       uid,
		Raw:       key.Raw,
		Prefix:    key.Prefix,
		ExpiresAt: exp,
	}, nil
}

func (s *APIKeysService) List(
	ctx context.Context,
	p *auth.Principal,
) ([]store.ApiKeysListByTenantRow, error) {
	rows, err := s.DB.ApiKeysListByTenant(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *APIKeysService) ListMine(
	ctx context.Context,
	p *auth.Principal,
) ([]store.ApiKeysListByUserRow, error) {
	rows, err := s.DB.ApiKeysListByUser(ctx, store.ApiKeysListByUserParams{
		TenantID: p.TenantID,
		UserID:   p.UserID,
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *APIKeysService) Revoke(
	ctx context.Context,
	p *auth.Principal,
	uid string,
) error {
	if err := ownerOrManager(p); err != nil {
		return err
	}
	if _, err := s.DB.ApiKeyRevoke(ctx, store.ApiKeyRevokeParams{
		Uid:      uid,
		TenantID: p.TenantID,
	}); err != nil {
		return msgErr(ErrNotFound, "api key not found")
	}
	return nil
}
