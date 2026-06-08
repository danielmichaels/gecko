package server

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/service"
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
	rows, err := app.Svc.UsersService().List(ctx, p)
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
	u, err := app.Svc.UsersService().Update(ctx, p, i.UID, service.UsersUpdateParams{
		Email: i.Body.Email,
		Name:  i.Body.Name,
		Role:  i.Body.Role,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			return nil, huma.Error403Forbidden(err.Error())
		case errors.Is(err, service.ErrNotFound):
			return nil, huma.Error404NotFound(err.Error())
		case errors.Is(err, service.ErrConflict):
			return nil, huma.Error409Conflict(err.Error())
		default:
			return nil, huma.Error500InternalServerError("failed to update user", err)
		}
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
	if err := app.Svc.UsersService().Delete(ctx, p, i.UID); err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			return nil, huma.Error403Forbidden(err.Error())
		case errors.Is(err, service.ErrNotFound):
			return nil, huma.Error404NotFound(err.Error())
		case errors.Is(err, service.ErrConflict):
			return nil, huma.Error409Conflict(err.Error())
		default:
			return nil, huma.Error500InternalServerError("failed to delete user", err)
		}
	}
	return &struct{}{}, nil
}
