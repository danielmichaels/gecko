package ui

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/service"
)

// SessionResolver is the subset of AuthService consumed by the browser middleware.
// Keeping the dependency narrow lets tests inject a simple fake without a live DB.
type SessionResolver interface {
	ResolveSession(ctx context.Context, rawToken string) (*auth.Principal, error)
}

// WebAuth is a middleware that requires a valid browser session. On success it
// injects the resolved Principal and a per-session CSRF token into the context.
//
// 303 See Other is used for all redirects so that browsers always re-issue the
// target as a GET, preventing POST data from being resent to the login page.
func (a *App) WebAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(a.cookieCfg.Name)
		if err != nil {
			http.Redirect(w, r, "/app/login", http.StatusSeeOther)
			return
		}

		rawToken := cookie.Value
		principal, err := a.resolver.ResolveSession(r.Context(), rawToken)
		if err != nil {
			if errors.Is(err, service.ErrUnauthenticated) {
				// Clear the stale cookie so the browser does not keep replaying it.
				ClearSessionCookie(w, a.cookieCfg)
				http.Redirect(w, r, "/app/login", http.StatusSeeOther)
				return
			}
			a.log.Error("unexpected session resolver error", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, principalKey, principal)
		ctx = context.WithValue(ctx, csrfTokenKey, csrfToken(a.csrfKey, rawToken))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
