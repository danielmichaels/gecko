package server

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type userView struct {
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UID       string     `json:"uid"`
	Email     string     `json:"email"`
	Name      string     `json:"name,omitempty"`
	Role      string     `json:"role"`
	Status    string     `json:"status"`
}

type ListUsersOutput struct {
	Body struct {
		Users []userView `json:"users"`
	}
}

// handleUserList lists the users in the caller's tenant. Any authenticated member
// may list; the query is tenant-scoped so no cross-tenant rows are returned.
func (app *Server) handleUserList(ctx context.Context, _ *struct{}) (*ListUsersOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := app.Db.UsersListByTenant(ctx, pgtype.Int4{Int32: p.TenantID, Valid: true})
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to list users", err)
	}
	out := &ListUsersOutput{}
	out.Body.Users = make([]userView, 0, len(rows))
	for _, u := range rows {
		out.Body.Users = append(out.Body.Users, userView{
			UID:       u.Uid,
			Email:     u.Email,
			Name:      u.Name.String,
			Role:      string(u.Role),
			Status:    string(u.Status),
			CreatedAt: tsPtr(u.CreatedAt),
		})
	}
	return out, nil
}

type UpdateUserInput struct {
	UID  string `path:"uid" example:"user_00000001"`
	Body struct {
		Email string `json:"email" required:"true" format:"email"`
		Name  string `json:"name,omitempty"`
		Role  string `json:"role"  required:"true" enum:"owner,manager,viewer" doc:"Role within the tenant; superadmin cannot be assigned via the API."`
	}
}

type UserOutput struct {
	Body userView
}

// handleUserUpdate updates a user in the caller's tenant. Owner/manager only; the
// role enum excludes superadmin so it cannot be granted here.
func (app *Server) handleUserUpdate(ctx context.Context, i *UpdateUserInput) (*UserOutput, error) {
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
	target, err := app.Db.UserGetInTenant(ctx, store.UserGetInTenantParams{
		Uid:      i.UID,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, huma.Error404NotFound("user not found")
		}
		return nil, huma.Error500InternalServerError("failed to update user", err)
	}
	if err := requireCanManage(p, string(target.Role)); err != nil {
		return nil, err
	}
	var u store.Users
	update := func(st *store.Queries) error {
		updated, err := st.UserUpdateInTenant(ctx, store.UserUpdateInTenantParams{
			Uid:      i.UID,
			TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
			Email:    normaliseEmail(i.Body.Email),
			Name:     pgtype.Text{String: i.Body.Name, Valid: i.Body.Name != ""},
			Role:     store.UserRole(i.Body.Role),
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return huma.Error404NotFound("user not found")
			}
			if isUniqueViolation(err) {
				return huma.Error409Conflict("email already in use")
			}
			return huma.Error500InternalServerError("failed to update user", err)
		}
		u = updated
		return nil
	}
	// Demoting an owner is guarded so the tenant cannot be left ownerless.
	demotingOwner := target.Role == store.UserRoleOwner &&
		store.UserRole(i.Body.Role) != store.UserRoleOwner
	if demotingOwner {
		if err := app.withLastOwnerGuard(ctx, p.TenantID, update); err != nil {
			return nil, err
		}
	} else if err := update(app.Db); err != nil {
		return nil, err
	}
	return &UserOutput{Body: userView{
		UID:       u.Uid,
		Email:     u.Email,
		Name:      u.Name.String,
		Role:      string(u.Role),
		Status:    string(u.Status),
		CreatedAt: tsPtr(u.CreatedAt),
	}}, nil
}

type DeleteUserInput struct {
	UID string `path:"uid" example:"user_00000001"`
}

// handleUserDelete removes a user from the caller's tenant. Owner/manager only.
func (app *Server) handleUserDelete(ctx context.Context, i *DeleteUserInput) (*struct{}, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	if err := ownerOrManager(p); err != nil {
		return nil, err
	}
	target, err := app.Db.UserGetInTenant(ctx, store.UserGetInTenantParams{
		Uid:      i.UID,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, huma.Error404NotFound("user not found")
		}
		return nil, huma.Error500InternalServerError("failed to delete user", err)
	}
	if err := requireCanManage(p, string(target.Role)); err != nil {
		return nil, err
	}
	del := func(st *store.Queries) error {
		if _, err := st.UserDeleteInTenant(ctx, store.UserDeleteInTenantParams{
			Uid:      i.UID,
			TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
		}); err != nil {
			return huma.Error404NotFound("user not found")
		}
		return nil
	}
	// Deleting an owner is guarded so the tenant cannot be left ownerless.
	if target.Role == store.UserRoleOwner {
		if err := app.withLastOwnerGuard(ctx, p.TenantID, del); err != nil {
			return nil, err
		}
	} else if err := del(app.Db); err != nil {
		return nil, err
	}
	return &struct{}{}, nil
}

// withLastOwnerGuard runs mutate inside a transaction after locking the tenant's
// owner rows FOR UPDATE and confirming more than one owner remains. The lock
// serialises concurrent owner removals so two callers cannot each observe a second
// owner that the other is deleting and both proceed, orphaning the tenant. mutate
// receives the transaction-scoped Queries and must return huma errors directly.
func (app *Server) withLastOwnerGuard(
	ctx context.Context,
	tenantID int32,
	mutate func(*store.Queries) error,
) error {
	tx, err := app.PgxPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return huma.Error500InternalServerError("operation failed", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := app.Db.WithTx(tx)

	owners, err := st.OwnersLockInTenant(ctx, pgtype.Int4{Int32: tenantID, Valid: true})
	if err != nil {
		return huma.Error500InternalServerError("operation failed", err)
	}
	if len(owners) <= 1 {
		return huma.Error409Conflict("cannot remove the last owner of a tenant")
	}
	if err := mutate(st); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return huma.Error500InternalServerError("operation failed", err)
	}
	return nil
}
