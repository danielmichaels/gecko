package dnsclient

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"
)

type fakeCacheStore struct {
	mu      sync.Mutex
	rows    map[string]store.DNSCacheUpsertParams
	gets    int
	upserts int
}

func newFakeCacheStore() *fakeCacheStore {
	return &fakeCacheStore{rows: make(map[string]store.DNSCacheUpsertParams)}
}

func fakeCacheKey(qtype int32, fqdn string) string {
	return fmt.Sprintf("%d|%s", qtype, fqdn)
}

func (f *fakeCacheStore) DNSCacheGet(
	_ context.Context,
	arg store.DNSCacheGetParams,
) (store.DNSCacheGetRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	row, ok := f.rows[fakeCacheKey(arg.Qtype, arg.Fqdn)]
	if !ok {
		return store.DNSCacheGetRow{}, pgx.ErrNoRows
	}
	if row.ExpiresAt.Valid && !row.ExpiresAt.Time.After(time.Now()) {
		return store.DNSCacheGetRow{}, pgx.ErrNoRows
	}
	return store.DNSCacheGetRow{
		Answers:   row.Answers,
		Status:    row.Status,
		ExpiresAt: row.ExpiresAt,
	}, nil
}

func (f *fakeCacheStore) DNSCacheUpsert(_ context.Context, arg store.DNSCacheUpsertParams) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upserts++
	f.rows[fakeCacheKey(arg.Qtype, arg.Fqdn)] = arg
	return nil
}

func startMock(t *testing.T) *testhelpers.MockDNSServer {
	t.Helper()
	mock, err := testhelpers.NewMockDNSServer()
	if err != nil {
		t.Fatalf("create mock dns server: %v", err)
	}
	if err := mock.Start(); err != nil {
		t.Fatalf("start mock dns server: %v", err)
	}
	t.Cleanup(func() { _ = mock.Stop() })
	return mock
}

func TestDNSCache_HitAvoidsWire(t *testing.T) {
	mock := startMock(t)
	if err := mock.AddRecord("example.com", dns.TypeA, 3600, "192.0.2.1"); err != nil {
		t.Fatalf("add record: %v", err)
	}
	client := New(
		WithServers([]string{mock.ListenAddr}),
		WithLogger(testhelpers.TestLogger),
		WithCache(newFakeCacheStore()),
	)

	for range 3 {
		if ans, ok := client.LookupA("example.com"); !ok || len(ans) != 1 {
			t.Fatalf("lookup failed: ok=%v ans=%v", ok, ans)
		}
	}
	if n := mock.QueryCount(); n != 1 {
		t.Fatalf("expected exactly 1 wire query across 3 cached lookups, got %d", n)
	}
}

func TestDNSCache_IndeterminateNotCached(t *testing.T) {
	mock := startMock(t)
	mock.SetRcode("bad.example.com", dns.RcodeServerFailure)
	client := New(
		WithServers([]string{mock.ListenAddr}),
		WithLogger(testhelpers.TestLogger),
		WithCache(newFakeCacheStore()),
	)

	for range 2 {
		if _, status := client.LookupWithStatus("bad.example.com", dns.TypeA); status != ResolutionIndeterminate {
			t.Fatalf("expected Indeterminate, got %v", status)
		}
	}
	if n := mock.QueryCount(); n != 2 {
		t.Fatalf("expected indeterminate results to bypass cache (2 queries), got %d", n)
	}
}

func TestDNSCache_SingleflightCollapsesConcurrent(t *testing.T) {
	dc := &dnsCache{
		store:       newFakeCacheStore(),
		l1:          newL1Cache(1000),
		ttl:         time.Minute,
		negativeTTL: time.Minute,
		logger:      testhelpers.TestLogger,
	}
	var fetches atomic.Int64
	fetch := func(string, uint16) ([]string, ResolutionStatus) {
		fetches.Add(1)
		time.Sleep(40 * time.Millisecond)
		return []string{"192.0.2.1"}, ResolutionData
	}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			dc.lookup("example.com", dns.TypeA, fetch)
		}()
	}
	wg.Wait()

	if got := fetches.Load(); got != 1 {
		t.Fatalf("expected singleflight to collapse to 1 fetch, got %d", got)
	}
}

// TestDNSCache_CompositeMethodCoverage proves caching reaches lookups made
// *inside* composite methods, not just direct interface calls: AttemptZoneTransfer
// resolves NS internally, and a later direct LookupNS must be served from cache.
func TestDNSCache_CompositeMethodCoverage(t *testing.T) {
	mock := startMock(t)
	if err := mock.AddRecord("example.com", dns.TypeNS, 3600, "ns1.example.com"); err != nil {
		t.Fatalf("add NS record: %v", err)
	}
	client := New(
		WithServers([]string{mock.ListenAddr}),
		WithLogger(testhelpers.TestLogger),
		WithCache(newFakeCacheStore()),
	)

	client.AttemptZoneTransfer("example.com")
	before := mock.QueryCount()

	if ns, ok := client.LookupNS("example.com"); !ok || len(ns) == 0 {
		t.Fatalf("expected NS lookup to succeed from cache: ok=%v ns=%v", ok, ns)
	}
	if after := mock.QueryCount(); after != before {
		t.Fatalf(
			"expected internal NS lookup to be cached (no new query); before=%d after=%d",
			before,
			after,
		)
	}
}

// TestDNSCache_IsZoneApexUsesCache proves the DNSSEC apex check shares the cached
// SOA path: repeated apex checks hit the wire once, and the entry is reused by a
// direct LookupSOA (same qtype+fqdn key).
func TestDNSCache_IsZoneApexUsesCache(t *testing.T) {
	mock := startMock(t)
	if err := mock.AddRecord(
		"example.com",
		dns.TypeSOA,
		3600,
		"ns1.example.com admin.example.com 1 7200 3600 1209600 3600",
	); err != nil {
		t.Fatalf("add SOA record: %v", err)
	}
	client := New(
		WithServers([]string{mock.ListenAddr}),
		WithLogger(testhelpers.TestLogger),
		WithCache(newFakeCacheStore()),
	)

	if !client.IsZoneApex("example.com") {
		t.Fatal("expected example.com to be detected as a zone apex")
	}
	if !client.IsZoneApex("example.com") {
		t.Fatal("expected apex (second call)")
	}
	if n := mock.QueryCount(); n != 1 {
		t.Fatalf("expected IsZoneApex to be cached (1 wire query), got %d", n)
	}

	before := mock.QueryCount()
	if _, ok := client.LookupSOA("example.com"); !ok {
		t.Fatal("expected SOA lookup to succeed")
	}
	if after := mock.QueryCount(); after != before {
		t.Fatalf(
			"expected LookupSOA to reuse the apex SOA cache entry; before=%d after=%d",
			before,
			after,
		)
	}
}

func TestEncodeDecodeDNSKEYRRSIG(t *testing.T) {
	tests := []struct {
		name    string
		dnskeys []string
		rrsigs  []string
	}{
		{name: "both populated", dnskeys: []string{"k1", "k2"}, rrsigs: []string{"s1"}},
		{name: "only dnskeys", dnskeys: []string{"k1"}, rrsigs: nil},
		{name: "both empty", dnskeys: nil, rrsigs: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDK, gotRS := decodeDNSKEYRRSIG(encodeDNSKEYRRSIG(tt.dnskeys, tt.rrsigs))
			if len(gotDK) != len(tt.dnskeys) {
				t.Fatalf("dnskeys: got %v want %v", gotDK, tt.dnskeys)
			}
			if len(gotRS) != len(tt.rrsigs) {
				t.Fatalf("rrsigs: got %v want %v", gotRS, tt.rrsigs)
			}
			for i := range tt.dnskeys {
				if gotDK[i] != tt.dnskeys[i] {
					t.Fatalf("dnskey[%d]: got %q want %q", i, gotDK[i], tt.dnskeys[i])
				}
			}
		})
	}
}

func TestDNSCache_CrossInstancePostgres(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	mock := startMock(t)
	if err := mock.AddRecord("example.com", dns.TypeA, 3600, "192.0.2.1"); err != nil {
		t.Fatalf("add record: %v", err)
	}

	// First instance populates the shared L2 from the wire.
	c1 := New(
		WithServers([]string{mock.ListenAddr}),
		WithLogger(testhelpers.TestLogger),
		WithCache(pc.Queries),
	)
	if _, ok := c1.LookupA("example.com"); !ok {
		t.Fatal("c1 lookup failed")
	}
	if n := mock.QueryCount(); n != 1 {
		t.Fatalf("expected 1 wire query from c1, got %d", n)
	}

	// Second instance has a cold L1 but shares the Postgres L2, so it must serve
	// the answer without hitting the wire.
	c2 := New(
		WithServers([]string{mock.ListenAddr}),
		WithLogger(testhelpers.TestLogger),
		WithCache(pc.Queries),
	)
	ans, ok := c2.LookupA("example.com")
	if !ok || !reflect.DeepEqual(ans, []string{"192.0.2.1"}) {
		t.Fatalf("c2 lookup: ok=%v ans=%v", ok, ans)
	}
	if n := mock.QueryCount(); n != 1 {
		t.Fatalf("expected c2 to be served from L2 (still 1 query), got %d", n)
	}
}
