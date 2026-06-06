package dnsclient

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/logging"
	"github.com/jackc/pgx/v5"
)

// RateLimitBucketKey is the single fleet-wide token-bucket row key. The startup
// seeder and the limiter must agree on it.
const RateLimitBucketKey = "global"

// rateLimitStore is the slice of *store.Queries the limiter needs, expressed as an
// interface so the acquire logic can be unit-tested without Postgres.
type rateLimitStore interface {
	RateLimitAcquire(ctx context.Context, key string) (float64, error)
}

// PgRateLimiter is a fleet-wide token-bucket limiter backed by a single Postgres
// row. Every gecko instance acquires from the same bucket, so the whole fleet
// shares one outbound-DNS budget.
type PgRateLimiter struct {
	store        rateLimitStore
	logger       *slog.Logger
	key          string
	maxWait      time.Duration
	pollInterval time.Duration
}

// NewPgRateLimiter builds a limiter from config. It returns nil when the feature
// is disabled or no store is supplied; a nil *PgRateLimiter is a valid no-op.
func NewPgRateLimiter(store rateLimitStore) *PgRateLimiter {
	cfg := config.AppConfig()
	if !cfg.AppConf.DNSRateLimitEnabled || store == nil {
		return nil
	}
	logger, _ := logging.SetupLogger("dns-ratelimit", cfg)
	return &PgRateLimiter{
		store:        store,
		key:          RateLimitBucketKey,
		maxWait:      cfg.AppConf.DNSRateLimitMaxWait,
		pollInterval: 50 * time.Millisecond,
		logger:       logger,
	}
}

// Acquire blocks until the fleet-wide bucket grants a token, returning true when
// the caller may issue a DNS query. It returns false ("shed") only when the budget
// stays exhausted for maxWait while Postgres is healthy. A real Postgres error
// degrades open (returns true) so an outage cannot halt all DNS resolution.
func (l *PgRateLimiter) Acquire() bool {
	if l == nil {
		return true
	}
	start := time.Now()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := l.store.RateLimitAcquire(ctx, l.key)
		cancel()
		switch {
		case err == nil:
			return true
		case errors.Is(err, pgx.ErrNoRows):
			if time.Since(start) >= l.maxWait {
				l.logger.Warn("dns rate limit exhausted; shedding query", "key", l.key)
				return false
			}
			time.Sleep(l.pollInterval)
		default:
			l.logger.Warn(
				"dns rate limiter degraded open (postgres error)",
				"key", l.key, "error", err,
			)
			return true
		}
	}
}
