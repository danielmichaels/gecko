package dnsclient

import (
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"
)

func shedLimiter() *PgRateLimiter {
	return &PgRateLimiter{
		store:        &fakeRateLimitStore{errs: []error{pgx.ErrNoRows}},
		key:          RateLimitBucketKey,
		maxWait:      0,
		pollInterval: time.Millisecond,
		logger:       slog.New(slog.DiscardHandler),
	}
}

func TestProbeNameserverRecordsAttempts(t *testing.T) {
	t.Run("shed limiter attempts nothing", func(t *testing.T) {
		c := &DNSClient{limiter: shedLimiter()}
		res := c.ProbeNameserver("127.0.0.1:1", "example.com", dns.TypeSOA)
		if res.Attempted || res.TCPAttempted {
			t.Fatalf("shed probe reported attempts: %+v", res)
		}
		if res.Reachable || res.TCPOK {
			t.Fatalf("shed probe reported contact: %+v", res)
		}
	})

	t.Run("nil limiter attempts both exchanges", func(t *testing.T) {
		c := &DNSClient{}
		res := c.ProbeNameserver("127.0.0.1:1", "example.com", dns.TypeSOA)
		if !res.Attempted || !res.TCPAttempted {
			t.Fatalf("probe did not record attempts: %+v", res)
		}
		if res.Reachable || res.TCPOK {
			t.Fatalf("closed port reported as reachable: %+v", res)
		}
	})
}
