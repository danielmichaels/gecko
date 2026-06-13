package config

import (
	"errors"
	"log"
	"log/slog"
	"strings"
	"time"

	"github.com/joeshaw/envdecode"
)

type Conf struct {
	Bootstrap bootstrapConf
	Mail      mailConf
	Db        dbConf
	Auth      authConf
	AppConf   appConf
	Server    serverConf
}

// bootstrapConf drives optional auto-bootstrap on `serve` startup: when Email and
// Password are both set, the server provisions the owner once (create-if-absent,
// so a restart never overwrites a changed password). Leave empty to disable.
type bootstrapConf struct {
	Email      string `env:"GECKO_BOOTSTRAP_EMAIL,default="`
	Password   string `env:"GECKO_BOOTSTRAP_PASSWORD,default="`
	TenantName string `env:"GECKO_BOOTSTRAP_TENANT_NAME,default=default"`
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
	// Session cookie settings used by the cookie-session system.
	SessionCookieName     string `env:"AUTH_SESSION_COOKIE_NAME,default=gecko_session"`
	SessionCookieSameSite string `env:"AUTH_SESSION_COOKIE_SAMESITE,default=lax"`
	// OIDC placeholders — reserved for the OIDC provider; empty until implemented.
	OIDCIssuer       string `env:"OIDC_ISSUER,default="`
	OIDCClientID     string `env:"OIDC_CLIENT_ID,default="`
	OIDCClientSecret string `env:"OIDC_CLIENT_SECRET,default="`
	OIDCRedirectURL  string `env:"OIDC_REDIRECT_URL,default="`
	// CSRFSecret is the HMAC key used to derive per-session CSRF tokens. If
	// empty at startup the server generates a random key — tokens will not
	// survive a restart in that case. Set AUTH_CSRF_SECRET in production.
	CSRFSecret string `env:"AUTH_CSRF_SECRET,default="`
	// BcryptCost is the bcrypt work factor for password hashing.
	BcryptCost int `env:"AUTH_BCRYPT_COST,default=12"`
	// APIKeyTTL bounds API key lifetime; 0 means keys never expire.
	APIKeyTTL time.Duration `env:"AUTH_APIKEY_TTL,default=0"`
	// InviteTTL bounds how long an invitation token stays valid.
	InviteTTL time.Duration `env:"AUTH_INVITE_TTL,default=168h"`
	// SessionTTL bounds cookie-session lifetime.
	SessionTTL time.Duration `env:"AUTH_SESSION_TTL,default=720h"`
	// ResetTTL bounds how long a password-reset token stays valid.
	ResetTTL time.Duration `env:"AUTH_RESET_TTL,default=1h"`
	// SignupEnabled toggles self-service tenant signup.
	SignupEnabled       bool `env:"SIGNUP_ENABLED,default=true"`
	SessionCookieSecure bool `env:"AUTH_SESSION_COOKIE_SECURE,default=true"`
}

type mailConf struct {
	// Driver selects the mail backend: "smtp" (go-mail), "log" (dev — logs the
	// envelope), or "noop" (tests — discards). Default keeps CI and non-Compose
	// runs working without an SMTP server.
	Driver   string `env:"MAIL_DRIVER,default=log"`
	SMTPHost string `env:"SMTP_HOST,default=localhost"`
	SMTPUser string `env:"SMTP_USERNAME,default="`
	SMTPPass string `env:"SMTP_PASSWORD,default="`
	FromAddr string `env:"MAIL_FROM,default=noreply@gecko.local"`
	SMTPPort int    `env:"SMTP_PORT,default=1025"`
}

type appConf struct {
	// Deprecated: the no-op X-API-Key check is replaced by real API-key auth in
	// internal/auth; this field is retained only so StrictDecode keeps parsing any
	// existing X_API_KEY env var. Not used by middleware.
	XApiKey string `env:"X_API_KEY,default=changeme"`
	// PublicBaseURL is the trusted public origin (scheme+host) used to build
	// absolute links in outbound email (e.g. password-reset). It MUST NOT be
	// derived from request headers: an attacker-controlled Host/X-Forwarded-Host
	// would poison the reset link and leak the token (reset poisoning). Empty
	// yields a host-less relative link rather than an attacker-controlled one.
	PublicBaseURL string `env:"APP_PUBLIC_URL,default="`
	// needs to be removed or made into a list a slice
	DNSServers              []string `env:"DNS_SERVERS,default=8.8.8.8:53;1.1.1.1:53;9.9.9.9:53"`
	SubfinderSources        []string `env:"SUBFINDER_SOURCES,default="`
	SubfinderExcludeSources []string `env:"SUBFINDER_EXCLUDE_SOURCES,default="`

	DNSBackoffBaseDelay int `env:"DNS_BACKOFF_BASE_DELAY,default=1"`
	DNSBackoffMaxDelay  int `env:"DNS_BACKOFF_MAX_DELAY,default=16"`
	DNSMaxRetries       int `env:"DNS_MAX_RETRIES,default=5"`

	DNSCacheTTL         time.Duration `env:"DNS_CACHE_TTL,default=5m"`
	DNSCacheNegativeTTL time.Duration `env:"DNS_CACHE_NEGATIVE_TTL,default=60s"`
	DNSCacheL1Size      int           `env:"DNS_CACHE_L1_SIZE,default=1000"`

	DNSRateLimitQPS     float64       `env:"DNS_RATE_LIMIT_QPS,default=100"`
	DNSRateLimitBurst   float64       `env:"DNS_RATE_LIMIT_BURST,default=200"`
	DNSRateLimitMaxWait time.Duration `env:"DNS_RATE_LIMIT_MAX_WAIT,default=10s"`

	EnumerationConcurrencyLimit int `env:"ENUMERATION_CONCURRENCY_LIMIT,default=100"`

	// EnumerationWorkerCount caps concurrent subdomain-enumeration jobs per process
	// independently of the general worker count, bounding pressure on subfinder's
	// upstream providers under HA. 0 falls back to the general worker count.
	EnumerationWorkerCount int `env:"ENUMERATION_WORKER_COUNT,default=10"`

	SubfinderRateLimit int `env:"SUBFINDER_RATE_LIMIT,default=0"`
	SubfinderTimeout   int `env:"SUBFINDER_TIMEOUT,default=30"`
	SubfinderMaxTime   int `env:"SUBFINDER_MAX_TIME,default=10"`

	// ScanRecencyWindow bounds how recently a discovered domain must have been
	// scanned to be skipped by the dedup guard. Explicit user actions (Force)
	// bypass this window.
	ScanRecencyWindow time.Duration `env:"SCAN_RECENCY_WINDOW,default=1h"`

	LogLevel slog.Level `env:"LOG_LEVEL,default=info"`

	// Fleet-wide shared DNS answer cache (Postgres L2 + in-process L1). Reused
	// across all instances so one lookup serves the whole fleet.
	DNSCacheEnabled bool `env:"DNS_CACHE_ENABLED,default=true"`

	// Global outbound-DNS rate limit shared by the whole fleet via a Postgres
	// token bucket. On exhaustion within DNSRateLimitMaxWait a query is shed
	// (degrade-closed); only a Postgres failure degrades open.
	DNSRateLimitEnabled bool `env:"DNS_RATE_LIMIT_ENABLED,default=true"`

	// Subfinder passive-enumeration tuning. Defaults reproduce the previous
	// hardcoded runner.Options exactly (Timeout=30s, MaxTime=10m, no rate cap, all
	// sources). SubfinderRateLimit caps subfinder's own outbound HTTP/sec to its
	// upstream providers (distinct from the DNS token bucket); 0 leaves subfinder
	// uncapped. Sources/ExcludeSources are ';'-separated (envdecode), like
	// DNS_SERVERS; empty means subfinder's default source set.
	SubfinderEnabled   bool `env:"SUBFINDER_ENABLED,default=true"`
	LogJson            bool `env:"LOG_JSON,default=false"`
	LogConcise         bool `env:"LOG_CONCISE,default=false"`
	LogResponseHeaders bool `env:"LOG_RESPONSE_HEADERS,default=false"`
	LogRequestHeaders  bool `env:"LOG_REQUEST_HEADERS,default=true"`

	// Certificate expiry assessment tiers (days until not_after). A certificate
	// already past not_after is critical; within High days is high; within Medium
	// days is medium; anything further out is compliant.
	CertExpiryHighDays   int `env:"CERT_EXPIRY_HIGH_DAYS,default=7"`
	CertExpiryMediumDays int `env:"CERT_EXPIRY_MEDIUM_DAYS,default=30"`
}
type serverConf struct {
	APIPort      int           `env:"GECKO_HTTP_PORT,default=9090"`
	TimeoutRead  time.Duration `env:"SERVER_TIMEOUT_READ,default=5s"`
	TimeoutIdle  time.Duration `env:"SERVER_TIMEOUT_IDLE,default=5s"`
	TimeoutWrite time.Duration `env:"SERVER_TIMEOUT_WRITE,default=5s"`
}

// Validate checks runtime preconditions a process must satisfy before it can
// serve. It is deliberately NOT called from AppConfig: tests and CLI commands
// load config without these set, so enforcement lives at the server entrypoint
// (serve_cmd) which calls this. Returns the first failing precondition.
func (c *Conf) Validate() error {
	// Only the smtp driver delivers real mail, so a missing public origin is only
	// a problem there; log/noop never put the link in front of a user.
	if c.Mail.Driver == "smtp" && strings.TrimSpace(c.AppConf.PublicBaseURL) == "" {
		return errors.New(
			"APP_PUBLIC_URL must be set when MAIL_DRIVER=smtp: it is the trusted public origin for links in outbound email (password reset, welcome)",
		)
	}
	return nil
}

// AppConfig Setup and install the applications' configuration environment variables
func AppConfig() *Conf {
	var c Conf
	if err := envdecode.StrictDecode(&c); err != nil {
		log.Fatalf("Failed to decode: %s", err)
	}
	return &c
}
