package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

func seedSPFFinding(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	domainID int32,
	severity store.FindingSeverity,
	issueType string,
) {
	t.Helper()
	if _, err := pc.Queries.AssessCreateSPFFinding(ctx, store.AssessCreateSPFFindingParams{
		DomainID:  pgtype.Int4{Int32: domainID, Valid: true},
		Severity:  severity,
		Status:    store.FindingStatusOpen,
		IssueType: issueType,
		Details:   pgtype.Text{String: issueType, Valid: true},
	}); err != nil {
		t.Fatalf("seed spf finding (domain %d): %v", domainID, err)
	}
}

func seedDMARCFinding(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	domainID int32,
	severity store.FindingSeverity,
	issueType string,
) {
	t.Helper()
	if _, err := pc.Queries.AssessCreateDMARCFinding(ctx, store.AssessCreateDMARCFindingParams{
		DomainID:  pgtype.Int4{Int32: domainID, Valid: true},
		Severity:  severity,
		Status:    store.FindingStatusOpen,
		IssueType: issueType,
		Details:   pgtype.Text{String: issueType, Valid: true},
	}); err != nil {
		t.Fatalf("seed dmarc finding (domain %d): %v", domainID, err)
	}
}

type findingsListResp struct {
	Pagination struct {
		Total    int64 `json:"total_results"`
		Page     int32 `json:"page"`
		PageSize int32 `json:"page_size"`
		Count    int32 `json:"count"`
	} `json:"pagination"`
	Findings []struct {
		DomainUID  string `json:"domain_uid"`
		DomainName string `json:"domain_name"`
		Kind       string `json:"kind"`
		Tier       string `json:"tier"`
	} `json:"findings"`
}

type domainFindingsResp struct {
	Summary struct {
		TotalCount    int `json:"total_count"`
		CriticalCount int `json:"critical_count"`
	} `json:"summary"`
	Findings []struct {
		Kind string `json:"kind"`
	} `json:"findings"`
}

// TestFindingsAPI exercises the findings REST endpoints through the full
// chi → huma → apiAuth chain: tenant-wide listing, pagination + the page-size cap,
// per-domain listing, and cross-tenant isolation on both routes.
func TestFindingsAPI(t *testing.T) {
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
	blog := seedDomain(t, ctx, pc, tenantA, "blog.example.org")
	secret := seedDomain(t, ctx, pc, tenantB, "secret.io")

	seedSPFFinding(t, ctx, pc, acme.ID, store.FindingSeverityCritical, "missing_spf")
	seedDMARCFinding(t, ctx, pc, acme.ID, store.FindingSeverityHigh, "weak_dmarc_policy")
	seedSPFFinding(t, ctx, pc, blog.ID, store.FindingSeverityMedium, "spf_softfail")
	seedSPFFinding(t, ctx, pc, secret.ID, store.FindingSeverityCritical, "missing_spf")

	t.Run("tenant listing is isolated", func(t *testing.T) {
		var resA findingsListResp
		if code := doJSON(t, http.MethodGet, base+"/api/findings", a.APIKey, nil, &resA); code != http.StatusOK {
			t.Fatalf("A /api/findings status = %d, want 200", code)
		}
		if resA.Pagination.Total != 3 {
			t.Errorf("A total = %d, want 3", resA.Pagination.Total)
		}
		for _, f := range resA.Findings {
			if f.DomainName == "secret.io" {
				t.Fatalf("A leaked tenant B finding for %q", f.DomainName)
			}
		}

		var resB findingsListResp
		if code := doJSON(t, http.MethodGet, base+"/api/findings", b.APIKey, nil, &resB); code != http.StatusOK {
			t.Fatalf("B /api/findings status = %d, want 200", code)
		}
		if resB.Pagination.Total != 1 || len(resB.Findings) != 1 ||
			resB.Findings[0].DomainName != "secret.io" {
			t.Errorf("B findings = %+v, want only secret.io", resB.Findings)
		}
	})

	t.Run("severity filter", func(t *testing.T) {
		var res findingsListResp
		if code := doJSON(t, http.MethodGet, base+"/api/findings?severity=crit", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if res.Pagination.Total != 1 || res.Findings[0].Tier != "crit" {
			t.Errorf("crit filter total = %d, want 1 crit", res.Pagination.Total)
		}
	})

	t.Run("page size is capped", func(t *testing.T) {
		var res findingsListResp
		if code := doJSON(t, http.MethodGet, base+"/api/findings?page_size=1000000", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if res.Pagination.PageSize > 100 {
			t.Errorf("page_size = %d, want clamped to <= 100", res.Pagination.PageSize)
		}
	})

	t.Run("pagination slices but total is full", func(t *testing.T) {
		var res findingsListResp
		if code := doJSON(t, http.MethodGet, base+"/api/findings?page_size=2", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if res.Pagination.Total != 3 || len(res.Findings) != 2 {
			t.Errorf("page1 total/len = %d/%d, want 3/2", res.Pagination.Total, len(res.Findings))
		}
	})

	t.Run("per-domain listing", func(t *testing.T) {
		var res domainFindingsResp
		if code := doJSON(t, http.MethodGet, base+"/api/domains/"+acme.Uid+"/findings", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		// acme has an SPF critical and a DMARC high; the 2-tier per-domain summary
		// collapses critical and high into the "crit" bucket.
		if res.Summary.TotalCount != 2 || res.Summary.CriticalCount != 2 {
			t.Errorf(
				"acme summary total/crit = %d/%d, want 2/2",
				res.Summary.TotalCount,
				res.Summary.CriticalCount,
			)
		}
	})

	t.Run("per-domain cross-tenant 404", func(t *testing.T) {
		if code := doJSON(t, http.MethodGet, base+"/api/domains/"+secret.Uid+"/findings", a.APIKey, nil, nil); code != http.StatusNotFound {
			t.Errorf("A -> B domain findings status = %d, want 404", code)
		}
	})

	t.Run("no key rejected", func(t *testing.T) {
		if code := doJSON(t, http.MethodGet, base+"/api/findings", "", nil, nil); code != http.StatusUnauthorized {
			t.Errorf("no key status = %d, want 401", code)
		}
	})
}
