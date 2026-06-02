package assessor

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

// TestAssessZoneTransfer_EmitsObservation proves that, when the assessor runs
// under a real scan identity, writing a zone-transfer finding also appends a
// "created" observation to the change log — the Phase 3 finding coverage that
// lets the corresponding *_history table be dropped.
func TestAssessZoneTransfer_EmitsObservation(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("Failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	domain, err := pc.Queries.DomainsGetByID(ctx, "domain_00000001")
	if err != nil {
		t.Fatalf("get domain: %v", err)
	}

	ident := observer.DomainIdentity{
		TenantID:   domain.TenantID.Int32,
		DomainID:   domain.ID,
		DomainUID:  domain.Uid,
		DomainName: domain.Name,
	}
	if !ident.Recordable() {
		t.Fatalf("seed domain identity not recordable: %+v", ident)
	}
	a := NewAssessor(Config{Store: pc.Queries, Logger: testhelpers.TestLogger, Identity: ident})

	js, err := json.Marshal(createMockZoneTransferData())
	if err != nil {
		t.Fatalf("marshal mock data: %v", err)
	}
	if _, err := pc.Queries.ScannersStoreZoneTransferAttempt(ctx, store.ScannersStoreZoneTransferAttemptParams{
		DomainID:      pgtype.Int4{Int32: domain.ID, Valid: true},
		Nameserver:    "ns1.example.com:53",
		TransferType:  "AXFR",
		WasSuccessful: true,
		ResponseData:  js,
	}); err != nil {
		t.Fatalf("seed attempt: %v", err)
	}

	if err := a.AssessZoneTransfer(ctx, domain.Uid); err != nil {
		t.Fatalf("AssessZoneTransfer: %v", err)
	}
	// Re-assessing the unchanged finding must NOT append a noise observation.
	if err := a.AssessZoneTransfer(ctx, domain.Uid); err != nil {
		t.Fatalf("AssessZoneTransfer (rerun): %v", err)
	}

	var count int
	var changeType string
	if err := pc.Pool.QueryRow(ctx,
		`SELECT count(*), coalesce(max(change_type), '') FROM domain_observations
		 WHERE tenant_id=$1 AND domain_name=$2 AND entity_type=$3`,
		domain.TenantID.Int32, domain.Name, observer.EntityZoneTransferFinding,
	).Scan(&count, &changeType); err != nil {
		t.Fatalf("count observations: %v", err)
	}
	if count != 1 {
		t.Errorf("zone-transfer finding observations = %d, want 1 (no noise on unchanged rerun)", count)
	}
	if changeType != "created" {
		t.Errorf("change_type = %q, want created", changeType)
	}
}
