package dnsclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/logging"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// qtypeDNSKEYWithRRSIG is a synthetic record type for caching the combined
// DNSKEY+RRSIG result under one key. It sits above the uint16 DNS qtype range so it
// cannot collide with a real record type.
const qtypeDNSKEYWithRRSIG uint16 = 0xF000

// rrsigSentinel separates the DNSKEY records from the RRSIG records packed into a
// single cached answers slice. It avoids null bytes, which Postgres text cannot
// store.
const rrsigSentinel = "__gecko_rrsig_sep__"

type cacheStore interface {
	DNSCacheGet(ctx context.Context, arg store.DNSCacheGetParams) (store.DNSCacheGetRow, error)
	DNSCacheUpsert(ctx context.Context, arg store.DNSCacheUpsertParams) error
}

type fetchFunc func(target string, qtype uint16) ([]string, ResolutionStatus)

// dnsCache is the fleet-wide shared answer cache: an in-process LRU (L1) in front
// of a Postgres table (L2), with singleflight to collapse concurrent identical
// lookups within a process.
type dnsCache struct {
	store       cacheStore
	sf          singleflight.Group
	l1          *l1Cache
	logger      *slog.Logger
	ttl         time.Duration
	negativeTTL time.Duration
}

// NewDNSCache builds the cache from config. It returns nil when caching is disabled
// or no store is supplied; a nil *dnsCache is a valid no-op.
func NewDNSCache(store cacheStore) *dnsCache {
	cfg := config.AppConfig()
	if !cfg.AppConf.DNSCacheEnabled || store == nil {
		return nil
	}
	logger, _ := logging.SetupLogger("dns-cache", cfg)
	return &dnsCache{
		store:       store,
		l1:          newL1Cache(cfg.AppConf.DNSCacheL1Size),
		ttl:         cfg.AppConf.DNSCacheTTL,
		negativeTTL: cfg.AppConf.DNSCacheNegativeTTL,
		logger:      logger,
	}
}

// WithCache enables the shared DNS cache backed by the given store. A disabled
// feature flag or nil store leaves the client uncached.
func WithCache(store cacheStore) DNSClientOption {
	return func(c *DNSClient) {
		c.cache = NewDNSCache(store)
	}
}

// resolve serves target/qtype from the shared cache, falling back to the wire on a
// miss. With caching disabled it is a direct wire lookup.
func (c *DNSClient) resolve(target string, qtype uint16) ([]string, ResolutionStatus) {
	if c.cache == nil {
		return c.lookupRecordWithStatus(target, qtype)
	}
	return c.cache.lookup(target, qtype, c.lookupRecordWithStatus)
}

// lookup reads the shared cache, and on a miss runs fetch under singleflight before
// caching any authoritative result. Indeterminate results are never cached.
func (dc *dnsCache) lookup(
	target string,
	qtype uint16,
	fetch fetchFunc,
) ([]string, ResolutionStatus) {
	key := cacheKey{qtype: qtype, fqdn: dns.Fqdn(target)}
	if e, ok := dc.read(key); ok {
		return e.answers, e.status
	}
	v, _, _ := dc.sf.Do(fmt.Sprintf("%d|%s", key.qtype, key.fqdn), func() (any, error) {
		if e, ok := dc.read(key); ok {
			return e, nil
		}
		answers, status := fetch(target, qtype)
		e := cacheEntry{answers: answers, status: status}
		if ttl := dc.ttlFor(status); ttl > 0 {
			e.expiresAt = time.Now().Add(ttl)
			dc.write(key, e)
		}
		return e, nil
	})
	e := v.(cacheEntry)
	return e.answers, e.status
}

func (dc *dnsCache) ttlFor(status ResolutionStatus) time.Duration {
	switch status {
	case ResolutionData:
		return dc.ttl
	case ResolutionEmpty:
		return dc.negativeTTL
	default:
		return 0
	}
}

func (dc *dnsCache) read(key cacheKey) (cacheEntry, bool) {
	now := time.Now()
	if e, ok := dc.l1.get(key, now); ok {
		return e, true
	}
	e, ok := dc.l2Get(key)
	if ok {
		dc.l1.set(key, e)
	}
	return e, ok
}

func (dc *dnsCache) l2Get(key cacheKey) (cacheEntry, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row, err := dc.store.DNSCacheGet(ctx, store.DNSCacheGetParams{
		Qtype: int32(key.qtype),
		Fqdn:  key.fqdn,
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			dc.logger.Warn("dns cache read failed", "error", err)
		}
		return cacheEntry{}, false
	}
	return cacheEntry{
		answers:   row.Answers,
		status:    ResolutionStatus(row.Status),
		expiresAt: row.ExpiresAt.Time,
	}, true
}

func (dc *dnsCache) write(key cacheKey, e cacheEntry) {
	answers := e.answers
	if answers == nil {
		answers = []string{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dc.store.DNSCacheUpsert(ctx, store.DNSCacheUpsertParams{
		Qtype:     int32(key.qtype),
		Fqdn:      key.fqdn,
		Answers:   answers,
		Status:    int16(e.status),
		ExpiresAt: pgtype.Timestamptz{Time: e.expiresAt, Valid: true},
	}); err != nil {
		dc.logger.Warn("dns cache write failed", "error", err)
	}
	dc.l1.set(key, e)
}

// LookupDNSKEYWithRRSIG performs a DNS query for the DNSKEY and RRSIG records for
// the given target domain, served from the shared cache when available. It returns
// the DNSKEY and RRSIG records, or false if the query was unsuccessful.
func (c *DNSClient) LookupDNSKEYWithRRSIG(target string) ([]string, []string, bool) {
	if c.cache == nil {
		return c.lookupDNSKEYWithRRSIGWire(target)
	}
	answers, status := c.cache.lookup(
		target,
		qtypeDNSKEYWithRRSIG,
		func(t string, _ uint16) ([]string, ResolutionStatus) {
			dnskeys, rrsigs, ok := c.lookupDNSKEYWithRRSIGWire(t)
			if !ok {
				return nil, ResolutionIndeterminate
			}
			return encodeDNSKEYRRSIG(dnskeys, rrsigs), ResolutionData
		},
	)
	if status != ResolutionData {
		return nil, nil, false
	}
	dnskeys, rrsigs := decodeDNSKEYRRSIG(answers)
	return dnskeys, rrsigs, true
}

func encodeDNSKEYRRSIG(dnskeys, rrsigs []string) []string {
	out := make([]string, 0, len(dnskeys)+len(rrsigs)+1)
	out = append(out, dnskeys...)
	out = append(out, rrsigSentinel)
	out = append(out, rrsigs...)
	return out
}

func decodeDNSKEYRRSIG(answers []string) ([]string, []string) {
	for i, a := range answers {
		if a == rrsigSentinel {
			return answers[:i:i], answers[i+1:]
		}
	}
	return answers, nil
}
