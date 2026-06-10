package scanner

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

// TestScanZoneTransferUsesIdentityTenant verifies the scanner looks the domain
// up by the identity's tenant rather than a hardcoded tenant ID (issue #28a):
// a tenant-2 domain must be found and its refused attempt recorded.
func TestScanZoneTransferUsesIdentityTenant(t *testing.T) {
	ctx := context.Background()
	pgContainer, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pgContainer.Close(ctx)

	domain, err := pgContainer.Queries.DomainsGetByID(
		ctx,
		store.DomainsGetByIDParams{
			Uid:      "domain_00000002",
			TenantID: pgtype.Int4{Int32: 2, Valid: true},
		},
	)
	if err != nil {
		t.Fatalf("Failed to get tenant-2 domain: %v", err)
	}

	fake := &fakeResolver{
		zoneTransferReturn: &dnsrecords.ZoneTransferResult{
			Domain: domain.Name,
			NS:     []string{"ns1.example-two.test."},
		},
	}
	s := NewScanner(Config{
		Logger:   testhelpers.TestLogger,
		Store:    pgContainer.Queries,
		Resolver: fake,
		Identity: observer.DomainIdentity{
			TenantID:   2,
			DomainID:   domain.ID,
			DomainUID:  domain.Uid,
			DomainName: domain.Name,
		},
	})

	uid, err := s.ScanZoneTransfer(ctx, domain.Name)
	if err != nil {
		t.Fatalf("ScanZoneTransfer failed for tenant-2 domain: %v", err)
	}
	if uid != domain.Uid {
		t.Errorf("Expected returned uid %q, got %q", domain.Uid, uid)
	}

	attempts, err := pgContainer.Queries.ScannersGetZoneTransferAttempts(
		ctx,
		pgtype.Int4{Int32: domain.ID, Valid: true},
	)
	if err != nil {
		t.Fatalf("Failed to get zone transfer attempts: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("Expected 1 recorded attempt, got %d", len(attempts))
	}
	if attempts[0].WasSuccessful {
		t.Error("Expected the recorded attempt to be a refusal")
	}
	if attempts[0].Nameserver != "ns1.example-two.test.:53" {
		t.Errorf("Unexpected nameserver: %q", attempts[0].Nameserver)
	}
}
