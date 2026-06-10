package ui

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/a-h/templ"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/ui/templates"
	"github.com/danielmichaels/gecko/internal/version"
	"github.com/go-chi/chi/v5"
	datastar "github.com/starfederation/datastar-go/datastar"
)

// Handlers holds dependencies for browser-facing route handlers.
type Handlers struct {
	svc       *service.Service
	app       *App
	log       *slog.Logger
	cookieCfg CookieConfig
}

// NewHandlers constructs a Handlers value wiring the service, middleware App,
// cookie config, and logger together.
func NewHandlers(
	svc *service.Service,
	app *App,
	cookieCfg CookieConfig,
	log *slog.Logger,
) *Handlers {
	if log == nil {
		log = slog.Default()
	}
	return &Handlers{
		svc:       svc,
		app:       app,
		cookieCfg: cookieCfg,
		log:       log,
	}
}

// Routes returns a chi router for all browser-facing routes.
// The router is intended to be mounted at /app by the server, so paths here do
// NOT include the /app prefix — chi's Mount strips it automatically.
func (h *Handlers) Routes() http.Handler {
	r := chi.NewRouter()

	// Public routes — no auth, no CSRF.
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/domains", http.StatusSeeOther)
	})
	r.Get("/login", h.handleLoginGet)
	r.Post("/login", h.handleLoginPost)
	r.Get("/invite", h.handleInviteGet)
	r.Post("/invite", h.handleInvitePost)

	// Protected routes — require a valid session and a matching CSRF token.
	r.Group(func(r chi.Router) {
		r.Use(h.app.WebAuth)
		r.Use(h.app.CSRFValidate)

		r.Post("/logout", h.handleLogoutPost)

		r.Get("/findings", h.handleFindingsPage)
		r.Get("/scans", h.handleScansPage)

		// ComingSoon placeholder pages.
		r.Get(
			"/dashboard",
			h.handleComingSoon(
				"dashboard",
				"⊞",
				"Dashboard",
				"A high-level overview of your fleet health and activity. Coming soon.",
			),
		)
		r.Get(
			"/team",
			h.handleComingSoon(
				"team",
				"⊕",
				"Team",
				"Manage teammates, roles, and pending invitations. Coming soon.",
			),
		)
		r.Get("/settings", h.handleSettingsGet)
		r.Post("/settings/apikeys", h.handleAPIKeyCreate)
		r.Delete("/settings/apikeys/{uid}", h.handleAPIKeyRevoke)
		r.Post("/settings/password", h.handlePasswordChange)

		r.Get("/domains", h.handleDomainsGet)
		r.Post("/domains", h.handleDomainCreate)
		r.Post("/domains/rescan", h.handleDomainsRescanAll)
		r.Get("/domains/{uid}", h.handleDomainDetail)
		r.Delete("/domains/{uid}", h.handleDomainDelete)
		r.Post("/domains/{uid}/rescan", h.handleDomainRescan)
		r.Get("/domains/{uid}/records", h.handleRecordsFragment)
		r.Get("/domains/{uid}/timeline", h.handleTimelineFragment)
		r.Get("/domains/{uid}/timeline/full", h.handleTimelineFullFragment)
		r.Get("/domains/{uid}/findings", h.handleFindingsFragment)
	})

	return r
}

// shell builds the AppShellProps required by every authenticated page.
// active is the nav key (e.g. "domains", "findings").
func (h *Handlers) shell(ctx context.Context, active string) (templates.AppShellProps, error) {
	p, ok := PrincipalFrom(ctx)
	if !ok {
		return templates.AppShellProps{}, fmt.Errorf("shell: no principal in context")
	}
	tenantName, _ := h.svc.AuthService().TenantName(ctx, p.TenantID)
	if tenantName == "" {
		tenantName = p.Email
	}
	return templates.AppShellProps{
		TenantName:       tenantName,
		UserEmail:        p.Email,
		UserInitials:     initials(p.Email),
		ActiveNav:        active,
		AppVersion:       version.Get(),
		ResolverOK:       true,
		CSRFToken:        CSRFTokenFrom(ctx),
		CanManageDomains: service.OwnerOrManager(p),
	}, nil
}

// handleLoginGet renders the login page.
func (h *Handlers) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.LoginPage(templates.LoginPageProps{}))
}

// handleLoginPost processes a datastar form POST for login.
func (h *Handlers) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := datastar.ReadSignals(r, &form); err != nil {
		h.log.Error("login: read signals", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	p, err := h.svc.AuthService().Authenticate(r.Context(), form.Email, form.Password)
	if err != nil {
		if errors.Is(err, service.ErrUnauthenticated) {
			sse := datastar.NewSSE(w, r)
			_ = sse.PatchElements(
				`<div id="login-error" style="color:var(--crit);font-family:var(--mono);font-size:12.5px;background:var(--crit-bg);border:1px solid var(--crit);border-radius:8px;padding:10px 14px;margin-bottom:12px;">invalid email or password</div>`,
			)
			return
		}
		h.log.Error("login: authenticate", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	rawToken, expiresAt, err := h.svc.AuthService().
		MintSession(r.Context(), p, r.UserAgent(), clientIP(r))
	if err != nil {
		h.log.Error("login: mint session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Cookie must be written before NewSSE flushes headers.
	SetSessionCookie(w, rawToken, expiresAt, h.cookieCfg)
	sse := datastar.NewSSE(w, r)
	_ = sse.Redirect("/app/domains")
}

// handleInviteGet renders the accept-invitation page for the given ?token=.
func (h *Handlers) handleInviteGet(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		renderPage(w, r, templates.ComingSoon(templates.ComingSoonProps{
			Glyph: "⚠",
			Title: "Invalid Invitation",
			Blurb: "No invitation token provided. Check your invitation link.",
		}))
		return
	}

	ic, err := h.svc.AuthService().InviteContextFromToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			renderPage(w, r, templates.ComingSoon(templates.ComingSoonProps{
				Glyph: "⚠",
				Title: "Invalid Invitation",
				Blurb: "This invitation link is invalid or has expired.",
			}))
			return
		}
		h.log.Error("invite: context lookup", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	renderPage(w, r, templates.AcceptInvitePage(templates.AcceptInvitePageProps{
		Token:        token,
		TenantName:   ic.TenantName,
		InviterEmail: "",
		Role:         ic.Role,
		InviteeEmail: ic.InviteeEmail,
		Expiry:       ic.Expiry,
	}))
}

// handleInvitePost processes the accept-invite datastar form POST.
func (h *Handlers) handleInvitePost(w http.ResponseWriter, r *http.Request) {
	var form struct {
		Token    string `json:"token"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := datastar.ReadSignals(r, &form); err != nil {
		h.log.Error("invite: read signals", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	p, err := h.svc.AuthService().AcceptInviteWeb(r.Context(), service.AcceptInviteParams{
		Token:    form.Token,
		Password: form.Password,
		Name:     form.Name,
	})
	if err != nil {
		sse := datastar.NewSSE(w, r)
		switch {
		case errors.Is(err, service.ErrNotFound):
			_ = sse.PatchElements(
				`<div id="invite-error" style="color:var(--crit);font-family:var(--mono);font-size:12.5px;background:var(--crit-bg);border:1px solid var(--crit);border-radius:8px;padding:10px 14px;margin-bottom:12px;">invalid or expired invitation</div>`,
			)
		case errors.Is(err, service.ErrConflict):
			_ = sse.PatchElements(
				`<div id="invite-error" style="color:var(--crit);font-family:var(--mono);font-size:12.5px;background:var(--crit-bg);border:1px solid var(--crit);border-radius:8px;padding:10px 14px;margin-bottom:12px;">email already registered</div>`,
			)
		default:
			h.log.Error("invite: accept", "error", err)
			_ = sse.PatchElements(
				`<div id="invite-error" style="color:var(--crit);font-family:var(--mono);font-size:12.5px;background:var(--crit-bg);border:1px solid var(--crit);border-radius:8px;padding:10px 14px;margin-bottom:12px;">something went wrong, please try again</div>`,
			)
		}
		return
	}

	rawToken, expiresAt, err := h.svc.AuthService().
		MintSession(r.Context(), p, r.UserAgent(), clientIP(r))
	if err != nil {
		h.log.Error("invite: mint session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Cookie must be written before NewSSE flushes headers.
	SetSessionCookie(w, rawToken, expiresAt, h.cookieCfg)
	sse := datastar.NewSSE(w, r)
	_ = sse.Redirect("/app/domains")
}

// handleLogoutPost revokes the session and redirects to login.
func (h *Handlers) handleLogoutPost(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cookieCfg.Name)
	if err == nil {
		if rErr := h.svc.AuthService().RevokeSession(r.Context(), cookie.Value); rErr != nil {
			h.log.Warn("logout: revoke session", "error", rErr)
		}
	}

	// Cookie cleared before NewSSE flushes headers.
	ClearSessionCookie(w, h.cookieCfg)
	sse := datastar.NewSSE(w, r)
	_ = sse.Redirect("/app/login")
}

// handleComingSoon returns a handler that renders the ComingSoon page for the
// given nav section.
func (h *Handlers) handleComingSoon(active, glyph, title, blurb string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		shell, err := h.shell(r.Context(), active)
		if err != nil {
			h.log.Error("coming soon: build shell", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		renderPage(w, r, templates.ComingSoon(templates.ComingSoonProps{
			Shell: shell,
			Glyph: glyph,
			Title: title,
			Blurb: blurb,
		}))
	}
}

// renderPage writes a full-page templ component to w.
func renderPage(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.Render(r.Context(), w); err != nil {
		slog.Error("render page", "error", err)
	}
}

// clientIP extracts the client IP from r.RemoteAddr. The chi RealIP middleware
// rewrites RemoteAddr to the real client IP from X-Forwarded-For/X-Real-IP,
// so this is correct for both direct and proxied connections.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// initials derives 1–2 uppercase letters from an email address for use as an
// avatar placeholder. Uses the local-part before the '@'.
func initials(email string) string {
	local := email
	if idx := strings.Index(email, "@"); idx > 0 {
		local = email[:idx]
	}
	local = strings.TrimSpace(local)
	if local == "" {
		return "?"
	}
	r, size := utf8.DecodeRuneInString(local)
	if r == utf8.RuneError || size == 0 {
		return "?"
	}
	first := strings.ToUpper(string(r))
	if idx := strings.IndexAny(local, "._-"); idx > 0 && idx+1 < len(local) {
		r2, _ := utf8.DecodeRuneInString(local[idx+1:])
		if r2 != utf8.RuneError {
			return first + strings.ToUpper(string(r2))
		}
	}
	return first
}
