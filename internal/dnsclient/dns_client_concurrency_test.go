package dnsclient

import (
	"sync"
	"testing"

	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/miekg/dns"
)

// TestDNSClient_ConcurrentLookupsRaceFree exercises a single *DNSClient shared
// across many goroutines, mirroring production where one resolver is injected into
// every worker. It must pass under `go test -race`: the round-robin server index
// must not be mutated without synchronization.
func TestDNSClient_ConcurrentLookupsRaceFree(t *testing.T) {
	mockServer, err := testhelpers.NewMockDNSServer()
	if err != nil {
		t.Fatalf("Failed to create mock DNS server: %v", err)
	}
	if err := mockServer.Start(); err != nil {
		t.Fatalf("Failed to start mock DNS server: %v", err)
	}
	defer func() { _ = mockServer.Stop() }()

	// The A record makes the name exist, so a DNSKEY query returns NOERROR/NODATA
	// rather than NXDOMAIN and reaches the success path that previously mutated the
	// shared server index.
	if err := mockServer.AddRecord("example.com", dns.TypeA, 3600, "192.0.2.1"); err != nil {
		t.Fatalf("Failed to add record: %v", err)
	}

	client := New(
		WithServers([]string{mockServer.ListenAddr}),
		WithLogger(testhelpers.TestLogger),
	)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			client.LookupDNSKEYWithRRSIG("example.com")
			client.LookupA("example.com")
		}()
	}
	wg.Wait()
}
