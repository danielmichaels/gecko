package ui

import (
	"context"

	"github.com/danielmichaels/gecko/internal/auth"
)

type contextKey string

const (
	principalKey  contextKey = "ui.principal"
	csrfTokenKey  contextKey = "ui.csrf_token"
)

// PrincipalFrom returns the authenticated Principal injected by WebAuth,
// and whether it was present.
func PrincipalFrom(ctx context.Context) (*auth.Principal, bool) {
	p, ok := ctx.Value(principalKey).(*auth.Principal)
	return p, ok
}

// CSRFTokenFrom returns the per-session CSRF token injected by WebAuth.
// Returns an empty string if absent (safe methods, or outside WebAuth).
func CSRFTokenFrom(ctx context.Context) string {
	t, _ := ctx.Value(csrfTokenKey).(string)
	return t
}
