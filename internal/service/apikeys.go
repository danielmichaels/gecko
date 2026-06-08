package service

import (
	"context"
	"fmt"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// APIKeysService exposes API key management business logic.
type APIKeysService struct {
	*Service
}

// APIKeysCreateResult holds the outcome of a successful Create call.
type APIKeysCreateResult struct {
	ExpiresAt pgtype.Timestamptz
	UID       string
	Raw       string
	Prefix    string
}

// Create mints a new API key for the caller's tenant. Owner/manager only.
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

// List returns all API keys scoped to the caller's tenant (never their secrets).
// Any authenticated member may list; the query is tenant-scoped.
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

// Revoke invalidates an API key in the caller's tenant. Owner/manager only.
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
