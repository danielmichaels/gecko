package dnsclient

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"
)

type fakeRateLimitStore struct {
	mu    sync.Mutex
	calls int
	errs  []error // consumed in order; the last entry repeats once exhausted
}

func (f *fakeRateLimitStore) RateLimitAcquire(_ context.Context, _ string) (float64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if len(f.errs) == 0 {
		return 0, nil
	}
	err := f.errs[0]
	if len(f.errs) > 1 {
		f.errs = f.errs[1:]
	}
	return 0, err
}

func (f *fakeRateLimitStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func testLimiter(s rateLimitStore) *PgRateLimiter {
	return &PgRateLimiter{
		store:        s,
		key:          "global",
		maxWait:      100 * time.Millisecond,
		pollInterval: 5 * time.Millisecond,
		logger:       testhelpers.TestLogger,
	}
}

func TestPgRateLimiter_GrantsWhenTokenAvailable(t *testing.T) {
	fake := &fakeRateLimitStore{}
	l := testLimiter(fake)
	if !l.Acquire() {
		t.Fatal("expected Acquire to grant when a token is available")
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected 1 store call, got %d", fake.callCount())
	}
}

func TestPgRateLimiter_ShedsWhenExhausted(t *testing.T) {
	fake := &fakeRateLimitStore{errs: []error{pgx.ErrNoRows}}
	l := testLimiter(fake)
	start := time.Now()
	if l.Acquire() {
		t.Fatal("expected Acquire to shed (return false) when budget is exhausted")
	}
	if elapsed := time.Since(start); elapsed < l.maxWait {
		t.Fatalf("expected to poll for at least maxWait (%s), only waited %s", l.maxWait, elapsed)
	}
}

func TestPgRateLimiter_DegradesOpenOnDBError(t *testing.T) {
	fake := &fakeRateLimitStore{errs: []error{errors.New("connection refused")}}
	l := testLimiter(fake)
	if !l.Acquire() {
		t.Fatal("expected Acquire to degrade open (return true) on a DB error")
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected to give up after 1 DB error, got %d calls", fake.callCount())
	}
}

func TestPgRateLimiter_GrantsAfterRefill(t *testing.T) {
	// First poll is exhausted, second succeeds — Acquire should keep polling and grant.
	fake := &fakeRateLimitStore{errs: []error{pgx.ErrNoRows, nil}}
	l := testLimiter(fake)
	if !l.Acquire() {
		t.Fatal("expected Acquire to grant once a token refills")
	}
	if fake.callCount() != 2 {
		t.Fatalf("expected 2 store calls (poll then grant), got %d", fake.callCount())
	}
}

func TestPgRateLimiter_NilIsNoop(t *testing.T) {
	var l *PgRateLimiter
	if !l.Acquire() {
		t.Fatal("nil limiter must be a no-op that always allows")
	}
}

func TestDNSClient_ShedsBeforeWire(t *testing.T) {
	mock, err := testhelpers.NewMockDNSServer()
	if err != nil {
		t.Fatalf("create mock dns server: %v", err)
	}
	if err := mock.Start(); err != nil {
		t.Fatalf("start mock dns server: %v", err)
	}
	defer func() { _ = mock.Stop() }()
	if err := mock.AddRecord("example.com", dns.TypeA, 3600, "192.0.2.1"); err != nil {
		t.Fatalf("add record: %v", err)
	}

	shed := &PgRateLimiter{
		store:        &fakeRateLimitStore{errs: []error{pgx.ErrNoRows}},
		key:          "global",
		maxWait:      20 * time.Millisecond,
		pollInterval: 5 * time.Millisecond,
		logger:       testhelpers.TestLogger,
	}
	client := New(
		WithServers([]string{mock.ListenAddr}),
		WithLogger(testhelpers.TestLogger),
		WithLimiter(shed),
	)

	answers, ok := client.LookupA("example.com")
	if ok || len(answers) != 0 {
		t.Fatalf("expected shed lookup to return no data, got ok=%v answers=%v", ok, answers)
	}
	if _, status := client.LookupWithStatus("example.com", dns.TypeA); status != ResolutionIndeterminate {
		t.Fatalf("expected ResolutionIndeterminate on shed, got %v", status)
	}
	if n := mock.QueryCount(); n != 0 {
		t.Fatalf("expected 0 wire queries when shedding, got %d", n)
	}
}

func TestPgRateLimiter_PostgresTokenBucket(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	// burst=2, near-zero refill so the bucket cannot replenish during the test.
	if err := pc.Queries.RateLimitUpsertBucket(ctx, store.RateLimitUpsertBucketParams{
		Key:     "global",
		Tokens:  2,
		RateQps: 0.0001,
		Burst:   2,
	}); err != nil {
		t.Fatalf("seed bucket: %v", err)
	}

	l := &PgRateLimiter{
		store:        pc.Queries,
		key:          "global",
		maxWait:      150 * time.Millisecond,
		pollInterval: 10 * time.Millisecond,
		logger:       testhelpers.TestLogger,
	}

	if !l.Acquire() {
		t.Fatal("first Acquire should be granted (burst token 1/2)")
	}
	if !l.Acquire() {
		t.Fatal("second Acquire should be granted (burst token 2/2)")
	}
	if l.Acquire() {
		t.Fatal("third Acquire should be shed: bucket exhausted and refill is negligible")
	}
}
