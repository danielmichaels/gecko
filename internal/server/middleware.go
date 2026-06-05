package server

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
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

// requireRole returns a 403 error unless the principal holds one of the given roles.
// huma does not enforce security scopes, so role gating happens here in Go.
func requireRole(p *auth.Principal, roles ...string) error {
	for _, r := range roles {
		if p.Role == r {
			return nil
		}
	}
	return huma.Error403Forbidden("insufficient permissions")
}

// roleRank orders roles by privilege; a higher number outranks a lower one. An
// unknown role ranks 0, so the grant check below fails closed for it. superadmin is
// included to outrank owner even though the API never assigns it.
var roleRank = map[string]int{
	string(store.UserRoleViewer):     1,
	string(store.UserRoleManager):    2,
	string(store.UserRoleOwner):      3,
	string(store.UserRoleSuperadmin): 4,
}

// requireCanGrant returns 403 unless the principal may assign target — an actor can
// never grant a role above their own. This complements ownerOrManager: that gate
// decides who may manage members, this caps how high they may promote, closing the
// manager→owner escalation (including self-promotion, where target outranks the
// manager's own role).
func requireCanGrant(p *auth.Principal, target string) error {
	if roleRank[p.Role] < roleRank[target] {
		return huma.Error403Forbidden("cannot grant a role above your own")
	}
	return nil
}

// requireCanManage returns 403 unless the principal outranks-or-equals the target
// user's current role. requireCanGrant guards the role being *set*; this guards the
// user being *acted on*, so a manager cannot demote, rewrite, or delete an owner. At
// or below the caller's own rank is allowed (owners manage owners; managers manage
// managers and viewers).
func requireCanManage(p *auth.Principal, targetRole string) error {
	if roleRank[p.Role] < roleRank[targetRole] {
		return huma.Error403Forbidden("cannot modify a user above your own role")
	}
	return nil
}
