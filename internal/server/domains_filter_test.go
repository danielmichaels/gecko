package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

type domainListResp struct {
	Pagination struct {
		Total    int64 `json:"total_results"`
		PageSize int32 `json:"page_size"`
		Count    int32 `json:"count"`
	} `json:"pagination"`
	Domains []struct {
		Domain     string `json:"domain"`
		DomainType string `json:"domain_type"`
		Source     string `json:"source"`
	} `json:"domains"`
}

func seedDomainTyped(
	t *testing.T,
	ctx context.Context,
	pc *testhelpers.PostgresContainer,
	tenantID int32,
	name string,
	domainType store.DomainType,
	source store.DomainSource,
) store.DomainsInsertRow {
	t.Helper()
	d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       name,
		DomainType: domainType,
		Source:     source,
		Status:     store.DomainStatusActive,
	})
	if err != nil {
		t.Fatalf("seed domain %s: %v", name, err)
	}
	return d
}

// TestDomainsListFilterAPI exercises GET /api/domains source/domain_type filters
// through the full chi → huma → apiAuth chain: each filter narrows the result,
// pagination total reflects the FILTERED set, tenancy holds, and an unknown enum
// value is rejected at the Huma boundary.
func TestDomainsListFilterAPI(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	a := signup(t, base, "owner@filter-a.com", "supersecret")
	signup(t, base, "owner@filter-b.com", "supersecret")
	tenantA := tenantIDByEmail(t, ctx, pc, "owner@filter-a.com")
	tenantB := tenantIDByEmail(t, ctx, pc, "owner@filter-b.com")

	seedDomainTyped(
		t,
		ctx,
		pc,
		tenantA,
		"apex.example.com",
		store.DomainTypeTld,
		store.DomainSourceUserSupplied,
	)
	seedDomainTyped(
		t,
		ctx,
		pc,
		tenantA,
		"sub.example.com",
		store.DomainTypeSubdomain,
		store.DomainSourceUserSupplied,
	)
	seedDomainTyped(
		t,
		ctx,
		pc,
		tenantA,
		"found.example.com",
		store.DomainTypeSubdomain,
		store.DomainSourceDiscovered,
	)
	// Tenant B domain that would match A's filters if isolation were broken.
	seedDomainTyped(
		t,
		ctx,
		pc,
		tenantB,
		"b-apex.example.com",
		store.DomainTypeTld,
		store.DomainSourceUserSupplied,
	)

	t.Run("filter by source narrows result", func(t *testing.T) {
		var res domainListResp
		if code := doJSON(t, http.MethodGet, base+"/api/domains?source=discovered", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if res.Pagination.Total != 1 || len(res.Domains) != 1 {
			t.Fatalf(
				"discovered total/len = %d/%d, want 1/1",
				res.Pagination.Total,
				len(res.Domains),
			)
		}
		if res.Domains[0].Domain != "found.example.com" || res.Domains[0].Source != "discovered" {
			t.Errorf("discovered domain = %+v, want found.example.com/discovered", res.Domains[0])
		}
	})

	t.Run("filter by domain_type narrows result", func(t *testing.T) {
		var res domainListResp
		if code := doJSON(t, http.MethodGet, base+"/api/domains?domain_type=tld", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if res.Pagination.Total != 1 || res.Domains[0].Domain != "apex.example.com" {
			t.Errorf(
				"tld total = %d, domain = %q, want 1 / apex.example.com",
				res.Pagination.Total,
				res.Domains[0].Domain,
			)
		}
	})

	t.Run("source and domain_type combine", func(t *testing.T) {
		var res domainListResp
		if code := doJSON(t, http.MethodGet, base+"/api/domains?source=user_supplied&domain_type=tld", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if res.Pagination.Total != 1 || res.Domains[0].Domain != "apex.example.com" {
			t.Errorf(
				"combined total = %d, domain = %q, want 1 / apex.example.com",
				res.Pagination.Total,
				res.Domains[0].Domain,
			)
		}
	})

	t.Run("total reflects filtered set under pagination", func(t *testing.T) {
		var res domainListResp
		if code := doJSON(t, http.MethodGet, base+"/api/domains?source=user_supplied&page_size=1", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		// Two user_supplied domains in tenant A; page slices to one, total stays 2
		// (the filtered total, not the tenant-wide 3).
		if res.Pagination.Total != 2 || res.Pagination.Count != 1 {
			t.Errorf(
				"paginated total/count = %d/%d, want 2/1",
				res.Pagination.Total,
				res.Pagination.Count,
			)
		}
	})

	t.Run("no filter is tenant-scoped", func(t *testing.T) {
		var res domainListResp
		if code := doJSON(t, http.MethodGet, base+"/api/domains", a.APIKey, nil, &res); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if res.Pagination.Total != 3 {
			t.Errorf("unfiltered total = %d, want 3 (tenant A only)", res.Pagination.Total)
		}
	})

	t.Run("unknown source value is rejected", func(t *testing.T) {
		if code := doJSON(t, http.MethodGet, base+"/api/domains?source=bogus", a.APIKey, nil, nil); code != http.StatusUnprocessableEntity {
			t.Errorf("bogus source status = %d, want 422", code)
		}
	})
}
