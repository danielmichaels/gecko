package server

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/jackc/pgx/v5/pgtype"
)

func tsPtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

type CreateAPIKeyInput struct {
	Body struct {
		Name string `json:"name" required:"true" doc:"A label to identify this key."`
	}
}

type CreateAPIKeyOutput struct {
	Body struct {
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
		UID       string     `json:"uid" doc:"Identifier used to revoke this key."`
		APIKey    string     `json:"api_key" doc:"The full key — shown once. Store it; it cannot be retrieved again."`
		Prefix    string     `json:"prefix"`
	}
}

// handleAPIKeyCreate mints a new API key for the caller's tenant. Owner/manager only.
func (app *Server) handleAPIKeyCreate(
	ctx context.Context,
	i *CreateAPIKeyInput,
) (*CreateAPIKeyOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	result, err := app.Svc.APIKeysService().Create(ctx, p, i.Body.Name)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			return nil, huma.Error403Forbidden(err.Error())
		default:
			return nil, huma.Error500InternalServerError("failed to create api key", err)
		}
	}
	out := &CreateAPIKeyOutput{}
	out.Body.UID = result.UID
	out.Body.APIKey = result.Raw
	out.Body.Prefix = result.Prefix
	out.Body.ExpiresAt = tsPtr(result.ExpiresAt)
	return out, nil
}

type apiKeyView struct {
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	UID        string     `json:"uid"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
}

type ListAPIKeysOutput struct {
	Body struct {
		APIKeys []apiKeyView `json:"api_keys"`
	}
}

// handleAPIKeyList lists the tenant's API keys (never their secrets).
func (app *Server) handleAPIKeyList(ctx context.Context, _ *struct{}) (*ListAPIKeysOutput, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := app.Svc.APIKeysService().List(ctx, p)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to list api keys", err)
	}
	out := &ListAPIKeysOutput{}
	out.Body.APIKeys = make([]apiKeyView, 0, len(rows))
	for _, r := range rows {
		out.Body.APIKeys = append(out.Body.APIKeys, apiKeyView{
			UID:        r.Uid,
			Name:       r.Name,
			Prefix:     r.Prefix,
			LastUsedAt: tsPtr(r.LastUsedAt),
			ExpiresAt:  tsPtr(r.ExpiresAt),
			RevokedAt:  tsPtr(r.RevokedAt),
			CreatedAt:  tsPtr(r.CreatedAt),
		})
	}
	return out, nil
}

type APIKeyRevokeInput struct {
	UID string `path:"uid" example:"apikey_00000001"`
}

// handleAPIKeyRevoke revokes a key in the caller's tenant. Owner/manager only.
func (app *Server) handleAPIKeyRevoke(
	ctx context.Context,
	i *APIKeyRevokeInput,
) (*struct{}, error) {
	p, err := principalOrErr(ctx)
	if err != nil {
		return nil, err
	}
	if err := app.Svc.APIKeysService().Revoke(ctx, p, i.UID); err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			return nil, huma.Error403Forbidden(err.Error())
		case errors.Is(err, service.ErrNotFound):
			return nil, huma.Error404NotFound(err.Error())
		default:
			return nil, huma.Error500InternalServerError("failed to revoke api key", err)
		}
	}
	return &struct{}{}, nil
}
