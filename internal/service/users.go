package service

import (
	"context"
	"errors"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// UsersService exposes user management business logic.
type UsersService struct {
	*Service
}

// UsersUpdateParams holds the caller-supplied fields for a user update.
type UsersUpdateParams struct {
	Email string
	Name  string
	Role  string
}

// List returns all users in the caller's tenant. Any authenticated member may
// list; the query is tenant-scoped so no cross-tenant rows are returned.
func (s *UsersService) List(ctx context.Context, p *auth.Principal) ([]store.Users, error) {
	rows, err := s.DB.UsersListByTenant(ctx, pgtype.Int4{Int32: p.TenantID, Valid: true})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// Update applies email/name/role changes to the target user, enforcing authz
// and the last-owner guard. Returns messaged sentinels so the handler can surface
// exact client-facing messages via err.Error().
func (s *UsersService) Update(
	ctx context.Context,
	p *auth.Principal,
	uid string,
	params UsersUpdateParams,
) (store.Users, error) {
	if err := ownerOrManager(p); err != nil {
		return store.Users{}, err
	}
	if err := requireCanGrant(p, params.Role); err != nil {
		return store.Users{}, err
	}
	target, err := s.DB.UserGetInTenant(ctx, store.UserGetInTenantParams{
		Uid:      uid,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return store.Users{}, msgErr(ErrNotFound, "user not found")
		}
		return store.Users{}, err
	}
	if err := requireCanManage(p, string(target.Role)); err != nil {
		return store.Users{}, err
	}

	var updated store.Users
	update := func(st *store.Queries) error {
		u, err := st.UserUpdateInTenant(ctx, store.UserUpdateInTenantParams{
			Uid:      uid,
			TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
			Email:    normaliseEmail(params.Email),
			Name:     pgtype.Text{String: params.Name, Valid: params.Name != ""},
			Role:     store.UserRole(params.Role),
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return msgErr(ErrNotFound, "user not found")
			}
			if isUniqueViolation(err) {
				return msgErr(ErrConflict, "email already in use")
			}
			return err
		}
		updated = u
		return nil
	}

	// Demoting an owner is guarded so the tenant cannot be left ownerless.
	demotingOwner := target.Role == store.UserRoleOwner &&
		store.UserRole(params.Role) != store.UserRoleOwner
	if demotingOwner {
		if err := s.withLastOwnerGuard(ctx, p.TenantID, update); err != nil {
			return store.Users{}, err
		}
	} else if err := update(s.DB); err != nil {
		return store.Users{}, err
	}
	return updated, nil
}

// Delete removes a user from the caller's tenant, enforcing authz and the
// last-owner guard.
func (s *UsersService) Delete(ctx context.Context, p *auth.Principal, uid string) error {
	if err := ownerOrManager(p); err != nil {
		return err
	}
	target, err := s.DB.UserGetInTenant(ctx, store.UserGetInTenantParams{
		Uid:      uid,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return msgErr(ErrNotFound, "user not found")
		}
		return err
	}
	if err := requireCanManage(p, string(target.Role)); err != nil {
		return err
	}

	del := func(st *store.Queries) error {
		if _, err := st.UserDeleteInTenant(ctx, store.UserDeleteInTenantParams{
			Uid:      uid,
			TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
		}); err != nil {
			return msgErr(ErrNotFound, "user not found")
		}
		return nil
	}

	// Deleting an owner is guarded so the tenant cannot be left ownerless.
	if target.Role == store.UserRoleOwner {
		return s.withLastOwnerGuard(ctx, p.TenantID, del)
	}
	return del(s.DB)
}

// withLastOwnerGuard runs mutate inside a transaction after locking the tenant's
// owner rows FOR UPDATE and confirming more than one owner remains. The lock
// serialises concurrent owner removals so two callers cannot each observe a second
// owner that the other is deleting and both proceed, orphaning the tenant. mutate
// receives the transaction-scoped Queries and must return messaged sentinels.
func (s *Service) withLastOwnerGuard(
	ctx context.Context,
	tenantID int32,
	mutate func(*store.Queries) error,
) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	owners, err := st.OwnersLockInTenant(ctx, pgtype.Int4{Int32: tenantID, Valid: true})
	if err != nil {
		return err
	}
	if len(owners) <= 1 {
		return msgErr(ErrConflict, "cannot remove the last owner of a tenant")
	}
	if err := mutate(st); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}
