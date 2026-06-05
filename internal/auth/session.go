package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionConfig configures the scs cookie-session manager used by the server-rendered
// web UI.
type SessionConfig struct {
	CookieName     string
	CookieSameSite string
	TTL            time.Duration
	CookieSecure   bool
}

const (
	sessionUserID   = "user_id"
	sessionTenantID = "tenant_id"
	sessionRole     = "role"
	sessionEmail    = "email"
)

// NewSessionManager builds an scs session manager backed by the pgx `sessions`
// table. It is constructed and held by the server now so the browser cookie path is
// ready; the HTML login route that calls PutPrincipal lands in the UI follow-up.
func NewSessionManager(pool *pgxpool.Pool, cfg SessionConfig) *scs.SessionManager {
	m := scs.New()
	m.Store = pgxstore.New(pool)
	m.Lifetime = cfg.TTL
	m.Cookie.Name = cfg.CookieName
	m.Cookie.Secure = cfg.CookieSecure
	m.Cookie.HttpOnly = true
	m.Cookie.SameSite = parseSameSite(cfg.CookieSameSite)
	return m
}

// PutPrincipal stores the authenticated identity in the current session.
func PutPrincipal(ctx context.Context, m *scs.SessionManager, p *Principal) {
	m.Put(ctx, sessionUserID, p.UserID)
	m.Put(ctx, sessionTenantID, p.TenantID)
	m.Put(ctx, sessionRole, p.Role)
	m.Put(ctx, sessionEmail, p.Email)
}

// GetPrincipal reconstructs the Principal from the current session, or returns false
// when the session carries no authenticated identity.
func GetPrincipal(ctx context.Context, m *scs.SessionManager) (*Principal, bool) {
	uid, ok := m.Get(ctx, sessionUserID).(int32)
	if !ok || uid == 0 {
		return nil, false
	}
	tid, _ := m.Get(ctx, sessionTenantID).(int32)
	return &Principal{
		UserID:   uid,
		TenantID: tid,
		Role:     m.GetString(ctx, sessionRole),
		Email:    m.GetString(ctx, sessionEmail),
	}, true
}

func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
