package config

import (
	"log"
	"log/slog"
	"time"

	"github.com/joeshaw/envdecode"
)

type Conf struct {
	Auth    authConf
	Db      dbConf
	AppConf appConf
	Server  serverConf
}

type dbConf struct {
	Host     string `env:"POSTGRES_HOST,default=localhost"`
	Db       string `env:"POSTGRES_DB,default=db"`
	User     string `env:"POSTGRES_USER,default=dbuser"`
	Password string `env:"POSTGRES_PASSWORD,default=dbuser"`
	// PG SSL MODES: allow, disable
	SSLMode  string `env:"POSTGRES_SSL_MODE,default=disable"`
	Port     int    `env:"POSTGRES_PORT,default=5432"`
	MaxConns int    `env:"POSTGRES_MAX_CONNS,default=16"`
}
type authConf struct {
	// Provider selects the auth backend: "local" (email/password) or "oidc" (stub).
	Provider string `env:"AUTH_PROVIDER,default=local"`
	// Session cookie settings (scs scaffolding for the future web UI).
	SessionCookieName     string `env:"AUTH_SESSION_COOKIE_NAME,default=gecko_session"`
	SessionCookieSameSite string `env:"AUTH_SESSION_COOKIE_SAMESITE,default=lax"`
	// OIDC placeholders — reserved for the OIDC provider; empty until implemented.
	OIDCIssuer       string `env:"OIDC_ISSUER,default="`
	OIDCClientID     string `env:"OIDC_CLIENT_ID,default="`
	OIDCClientSecret string `env:"OIDC_CLIENT_SECRET,default="`
	OIDCRedirectURL  string `env:"OIDC_REDIRECT_URL,default="`
	// BcryptCost is the bcrypt work factor for password hashing.
	BcryptCost int `env:"AUTH_BCRYPT_COST,default=12"`
	// APIKeyTTL bounds API key lifetime; 0 means keys never expire.
	APIKeyTTL time.Duration `env:"AUTH_APIKEY_TTL,default=0"`
	// InviteTTL bounds how long an invitation token stays valid.
	InviteTTL time.Duration `env:"AUTH_INVITE_TTL,default=168h"`
	// SessionTTL bounds browser (scs) session lifetime.
	SessionTTL time.Duration `env:"AUTH_SESSION_TTL,default=720h"`
	// SignupEnabled toggles self-service tenant signup.
	SignupEnabled       bool `env:"SIGNUP_ENABLED,default=true"`
	SessionCookieSecure bool `env:"AUTH_SESSION_COOKIE_SECURE,default=true"`
}

type appConf struct {
	// Deprecated: the no-op X-API-Key check is replaced by real API-key auth in
	// internal/auth; this field is retained only so StrictDecode keeps parsing any
	// existing X_API_KEY env var. Not used by middleware.
	XApiKey string `env:"X_API_KEY,default=changeme"`
	// needs to be removed or made into a list a slice
	DNSServers          []string `env:"DNS_SERVERS,default=8.8.8.8:53;1.1.1.1:53;9.9.9.9:53"`
	DNSBackoffBaseDelay int      `env:"DNS_BACKOFF_BASE_DELAY,default=1"`
	DNSBackoffMaxDelay  int      `env:"DNS_BACKOFF_MAX_DELAY,default=16"`
	DNSMaxRetries       int      `env:"DNS_MAX_RETRIES,default=5"`

	EnumerationConcurrencyLimit int `env:"ENUMERATION_CONCURRENCY_LIMIT,default=100"`

	// ScanRecencyWindow bounds how recently a discovered domain must have been
	// scanned to be skipped by the dedup guard. Explicit user actions (Force)
	// bypass this window.
	ScanRecencyWindow time.Duration `env:"SCAN_RECENCY_WINDOW,default=1h"`

	LogLevel           slog.Level `env:"LOG_LEVEL,default=info"`
	LogJson            bool       `env:"LOG_JSON,default=false"`
	LogConcise         bool       `env:"LOG_CONCISE,default=false"`
	LogResponseHeaders bool       `env:"LOG_RESPONSE_HEADERS,default=false"`
	LogRequestHeaders  bool       `env:"LOG_REQUEST_HEADERS,default=true"`
}
type serverConf struct {
	APIPort      int           `env:"API_SERVER_PORT,default=9090"`
	TimeoutRead  time.Duration `env:"SERVER_TIMEOUT_READ,default=5s"`
	TimeoutIdle  time.Duration `env:"SERVER_TIMEOUT_IDLE,default=5s"`
	TimeoutWrite time.Duration `env:"SERVER_TIMEOUT_WRITE,default=5s"`
}

// AppConfig Setup and install the applications' configuration environment variables
func AppConfig() *Conf {
	var c Conf
	if err := envdecode.StrictDecode(&c); err != nil {
		log.Fatalf("Failed to decode: %s", err)
	}
	return &c
}
