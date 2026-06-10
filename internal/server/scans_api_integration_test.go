package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

func seedScanRow(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	tenantID int32,
	d store.DomainsInsertRow,
	source store.DomainSource,
	parent pgtype.Int8,
) store.Scans {
	t.Helper()
	s, err := pc.Queries.ScansCreate(ctx, store.ScansCreateParams{
		TenantID:     tenantID,
		DomainID:     pgtype.Int4{Int32: d.ID, Valid: true},
		DomainUid:    d.Uid,
		DomainName:   d.Name,
		ParentScanID: parent,
		Source:       source,
	})
	if err != nil {
		t.Fatalf("seed scan (%s): %v", d.Name, err)
	}
	return s
}

func seedObs(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	tenantID int32,
	d store.DomainsInsertRow,
	scanID int64,
	entityKey, changeType string,
) {
	t.Helper()
	if _, err := pc.Queries.ObservationsCreate(ctx, store.ObservationsCreateParams{
		TenantID:   tenantID,
		DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
		DomainUid:  d.Uid,
		DomainName: d.Name,
		ScanID:     pgtype.Int8{Int64: scanID, Valid: true},
		EntityType: "a_record",
		EntityKey:  entityKey,
		ChangeType: changeType,
		Payload:    []byte(`{}`),
	}); err != nil {
		t.Fatalf("seed observation: %v", err)
	}
}

type scansListResp struct {
	Pagination struct {
		Total    int64 `json:"total_results"`
		PageSize int32 `json:"page_size"`
	} `json:"pagination"`
	Scans []struct {
		ScanUID    string `json:"scan_uid"`
		DomainName string `json:"domain_name"`
		Source     string `json:"source"`
		State      string `json:"state"`
	} `json:"scans"`
}

func (r scansListResp) hasScan(uid string) bool {
	for _, s := range r.Scans {
		if s.ScanUID == uid {
			return true
		}
	}
	return false
}

// TestScansAPI exercises the /api/scans feed through the full chi → huma → apiAuth
// chain: tenant isolation, the default 7-day window (and the all-time escape hatch),
// source filtering, and missing-key rejection.
func TestScansAPI(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	a := signup(t, base, "owner@a.com", "supersecret")
	b := signup(t, base, "owner@b.com", "supersecret")
	tenantA := tenantIDByEmail(t, ctx, pc, "owner@a.com")
	tenantB := tenantIDByEmail(t, ctx, pc, "owner@b.com")

	acme := seedDomain(t, ctx, pc, tenantA, "acme.com")
	disc := seedDomain(t, ctx, pc, tenantA, "disc.example.org")
	other := seedDomain(t, ctx, pc, tenantB, "other.com")

	recent := seedScanRow(t, ctx, pc, tenantA, acme, store.DomainSourceUserSupplied, pgtype.Int8{})
	seedObs(t, ctx, pc, tenantA, acme, recent.ID, "a1", "created")
	discScan := seedScanRow(t, ctx, pc, tenantA, disc, store.DomainSourceDiscovered, pgtype.Int8{})
	seedObs(t, ctx, pc, tenantA, disc, discScan.ID, "a1", "created")
	otherScan := seedScanRow(
		t,
		ctx,
		pc,
		tenantB,
		other,
		store.DomainSourceUserSupplied,
		pgtype.Int8{},
	)
	seedObs(t, ctx, pc, tenantB, other, otherScan.ID, "a1", "created")

	t.Run("tenant feed is isolated", func(t *testing.T) {
		var res scansListResp
		if code := doJSON(t, http.MethodGet, base+"/api/scans", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if res.Pagination.Total != 2 {
			t.Errorf("A total = %d, want 2", res.Pagination.Total)
		}
		if res.hasScan(otherScan.Uid) {
			t.Fatalf("A leaked tenant B scan %s", otherScan.Uid)
		}

		var resB scansListResp
		if code := doJSON(t, http.MethodGet, base+"/api/scans", b.APIKey, nil, &resB); code != http.StatusOK {
			t.Fatalf("B status = %d, want 200", code)
		}
		if resB.Pagination.Total != 1 || !resB.hasScan(otherScan.Uid) {
			t.Errorf("B feed = %+v, want only its own scan", resB.Scans)
		}
	})

	t.Run("default window excludes old scans, all-time includes them", func(t *testing.T) {
		old := time.Now().Add(-30 * 24 * time.Hour)
		if _, err := pc.Pool.Exec(ctx,
			"UPDATE scans SET started_at = $1 WHERE id = $2", old, discScan.ID); err != nil {
			t.Fatalf("backdate scan: %v", err)
		}

		var def scansListResp
		if code := doJSON(t, http.MethodGet, base+"/api/scans", a.APIKey, nil, &def); code != http.StatusOK {
			t.Fatalf("default status = %d, want 200", code)
		}
		if def.hasScan(discScan.Uid) {
			t.Errorf("30-day-old scan present under default 7-day window")
		}

		var all scansListResp
		if code := doJSON(t, http.MethodGet, base+"/api/scans?window_days=0", a.APIKey, nil, &all); code != http.StatusOK {
			t.Fatalf("all-time status = %d, want 200", code)
		}
		if !all.hasScan(discScan.Uid) {
			t.Errorf("30-day-old scan missing under all-time window")
		}
	})

	t.Run("source filter", func(t *testing.T) {
		var res scansListResp
		if code := doJSON(t, http.MethodGet, base+"/api/scans?source=user_supplied&window_days=0", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		for _, s := range res.Scans {
			if s.Source != "user_supplied" {
				t.Errorf("source filter returned %q", s.Source)
			}
		}
		if !res.hasScan(recent.Uid) {
			t.Errorf("user_supplied scan missing under source filter")
		}
	})

	t.Run("no key rejected", func(t *testing.T) {
		if code := doJSON(t, http.MethodGet, base+"/api/scans", "", nil, nil); code != http.StatusUnauthorized {
			t.Errorf("no key status = %d, want 401", code)
		}
	})
}
