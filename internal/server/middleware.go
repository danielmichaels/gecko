package server

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/auth"
)

type contextKey string

const (
	principalKey contextKey = "principal"
	apiKeyUIDKey contextKey = "api_key_uid"
)

// apiAuth authenticates an API request via the X-API-Key header. On success it
// injects the resolved Principal and the presenting key's uid into the request
// context; otherwise it short-circuits with 401. Every failure returns the same
// opaque "unauthorized" so callers cannot tell why a key was rejected.
func (app *Server) apiAuth(api huma.API) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		raw := ctx.Header("X-API-Key")
		if raw == "" {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}
		p, keyUID, err := auth.VerifyAPIKey(ctx.Context(), app.Db, raw)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx = huma.WithValue(ctx, principalKey, p)
		ctx = huma.WithValue(ctx, apiKeyUIDKey, keyUID)
		next(ctx)
	}
}

// principalFromContext returns the authenticated Principal injected by apiAuth.
func principalFromContext(ctx context.Context) (*auth.Principal, bool) {
	p, ok := ctx.Value(principalKey).(*auth.Principal)
	return p, ok
}

// principalOrErr returns the authenticated Principal or a 401 error. Protected
// handlers call this to obtain the caller's tenant; apiAuth guarantees it is
// present, so the error path is defence-in-depth.
func principalOrErr(ctx context.Context) (*auth.Principal, error) {
	p, ok := principalFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	return p, nil
}

// apiKeyUIDFromContext returns the uid of the API key that authenticated the
// request, used by logout to revoke exactly that key.
func apiKeyUIDFromContext(ctx context.Context) (string, bool) {
	uid, ok := ctx.Value(apiKeyUIDKey).(string)
	return uid, ok
}
