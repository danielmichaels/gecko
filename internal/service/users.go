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

// Member is a tenant member: a user identity plus the role they hold in the
// caller's tenant. Role and JoinedAt come from the membership; email/name/status
// from the shared identity.
type Member struct {
	JoinedAt pgtype.Timestamptz
	UID      string
	Email    string
	Name     string
	Role     string
	Status   string
	UserID   int32
}

// UsersUpdateParams holds the caller-supplied fields for a user update.
type UsersUpdateParams struct {
	Role string
}

// List returns the members of the caller's tenant with their per-tenant role. Any
// authenticated member may list; the query is tenant-scoped so no cross-tenant
// rows are returned.
func (s *UsersService) List(ctx context.Context, p *auth.Principal) ([]Member, error) {
	rows, err := s.DB.MembershipsListByTenant(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	members := make([]Member, len(rows))
	for i, r := range rows {
		members[i] = Member{
			UserID:   r.UserID,
			UID:      r.UserUid,
			Email:    r.Email,
			Name:     r.Name.String,
			Role:     string(r.Role),
			Status:   string(r.Status),
			JoinedAt: r.JoinedAt,
		}
	}
	return members, nil
}

// Update applies email/name/role changes to a member of the caller's tenant,
// enforcing authz and the last-owner guard. Email/name update the shared identity;
// role updates the membership. Returns messaged sentinels so the handler can
// surface exact client-facing messages via err.Error().
func (s *UsersService) Update(
	ctx context.Context,
	p *auth.Principal,
	uid string,
	params UsersUpdateParams,
) (Member, error) {
	if err := ownerOrManager(p); err != nil {
		return Member{}, err
	}
	if err := requireCanGrant(p, params.Role); err != nil {
		return Member{}, err
	}
	target, err := s.DB.MembershipGetInTenant(ctx, store.MembershipGetInTenantParams{
		Uid:      uid,
		TenantID: p.TenantID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Member{}, msgErr(ErrNotFound, "user not found")
		}
		return Member{}, err
	}
	if err := requireCanManage(p, string(target.Role)); err != nil {
		return Member{}, err
	}

	mutate := func(st *store.Queries) error {
		if _, err := st.MembershipUpdateRole(ctx, store.MembershipUpdateRoleParams{
			Uid:      uid,
			TenantID: p.TenantID,
			Role:     store.UserRole(params.Role),
		}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return msgErr(ErrNotFound, "user not found")
			}
			return err
		}
		return nil
	}

	// Demoting an owner is guarded so the tenant cannot be left ownerless.
	demotingOwner := target.Role == store.UserRoleOwner &&
		store.UserRole(params.Role) != store.UserRoleOwner
	if demotingOwner {
		if err := s.withLastOwnerGuard(ctx, p.TenantID, mutate); err != nil {
			return Member{}, err
		}
	} else if err := s.inTx(ctx, mutate); err != nil {
		return Member{}, err
	}

	updated, err := s.DB.MembershipGetInTenant(ctx, store.MembershipGetInTenantParams{
		Uid:      uid,
		TenantID: p.TenantID,
	})
	if err != nil {
		return Member{}, err
	}
	return Member{
		UserID:   updated.UserID,
		UID:      updated.UserUid,
		Email:    updated.Email,
		Name:     updated.Name.String,
		Role:     string(updated.Role),
		Status:   string(updated.Status),
		JoinedAt: updated.JoinedAt,
	}, nil
}

// Delete removes a member from the caller's tenant, enforcing authz and the
// last-owner guard. Only the membership is deleted: the user's identity and their
// memberships in other tenants survive.
func (s *UsersService) Delete(ctx context.Context, p *auth.Principal, uid string) error {
	if err := ownerOrManager(p); err != nil {
		return err
	}
	target, err := s.DB.MembershipGetInTenant(ctx, store.MembershipGetInTenantParams{
		Uid:      uid,
		TenantID: p.TenantID,
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
		if _, err := st.MembershipDelete(ctx, store.MembershipDeleteParams{
			Uid:      uid,
			TenantID: p.TenantID,
		}); err != nil {
			return msgErr(ErrNotFound, "user not found")
		}
		return nil
	}

	// Removing an owner is guarded so the tenant cannot be left ownerless.
	if target.Role == store.UserRoleOwner {
		return s.withLastOwnerGuard(ctx, p.TenantID, del)
	}
	return del(s.DB)
}

// inTx runs mutate inside a transaction, committing on success. Used by callers
// that need a multi-statement mutation to be atomic but do not need the owner lock.
func (s *Service) inTx(ctx context.Context, mutate func(*store.Queries) error) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := mutate(s.DB.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// withLastOwnerGuard runs mutate inside a transaction after locking the tenant's
// owner memberships FOR UPDATE and confirming more than one owner remains. The lock
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

	owners, err := st.MembershipOwnersLockInTenant(ctx, tenantID)
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
