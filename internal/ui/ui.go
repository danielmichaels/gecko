// Package ui provides browser-facing HTTP middleware and helpers: session
// resolution, per-session CSRF protection, and cookie management.
package ui

import (
	"log/slog"
	"net/http"
)

// CookieConfig holds session cookie attributes that are fixed at startup.
// Expiry is passed per-call to SetSessionCookie because it varies per session.
type CookieConfig struct {
	Name     string
	SameSite http.SameSite
	Secure   bool
}

// App holds the shared dependencies for browser-facing middleware.
type App struct {
	resolver  SessionResolver
	log       *slog.Logger
	csrfKey   []byte
	cookieCfg CookieConfig
}

// New constructs an App. A nil logger falls back to slog.Default() so callers
// in tests that pass nil never trigger a nil-pointer dereference on log calls.
func New(resolver SessionResolver, cfg CookieConfig, csrfKey []byte, log *slog.Logger) *App {
	if log == nil {
		log = slog.Default()
	}
	return &App{
		resolver:  resolver,
		cookieCfg: cfg,
		csrfKey:   csrfKey,
		log:       log,
	}
}
