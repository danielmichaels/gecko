package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/danielmichaels/gecko/internal/jobs"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// DomainsService exposes domain CRUD business logic.
type DomainsService struct {
	*Service
}

// DomainsListParams carries pagination and optional search filter for List.
type DomainsListParams struct {
	FilterName string
	PageSize   int32
	Offset     int32
}

// DomainsListResult holds a page of domains plus the tenant-wide total.
type DomainsListResult struct {
	Domains    []store.Domains
	TotalCount int64
}

// DomainsCreateParams holds the caller-supplied fields for a new domain.
type DomainsCreateParams struct {
	Domain     string
	DomainType string
	Source     string
	Status     string
}

// DomainsUpdateParams carries partial-update fields; empty string means keep existing.
type DomainsUpdateParams struct {
	DomainType string
	Source     string
	Status     string
}

// List returns a tenant-scoped page of domains, optionally filtered by name.
// The search branch wraps the filter with a LIKE wildcard.
func (s *DomainsService) List(
	ctx context.Context,
	p *auth.Principal,
	params DomainsListParams,
) (DomainsListResult, error) {
	tenantID := pgtype.Int4{Int32: p.TenantID, Valid: true}

	if params.FilterName != "" {
		rows, err := s.DB.DomainsSearchByName(ctx, store.DomainsSearchByNameParams{
			TenantID: tenantID,
			Name:     "%" + params.FilterName + "%",
			Limit:    params.PageSize,
			Offset:   params.Offset,
		})
		if err != nil {
			return DomainsListResult{}, fmt.Errorf("domains search: %w", err)
		}
		var total int64
		if len(rows) > 0 {
			total = rows[0].TotalCount
		}
		return DomainsListResult{
			Domains:    dto.DomainSearchByNameRowToDomains(rows),
			TotalCount: total,
		}, nil
	}

	rows, err := s.DB.DomainsListByTenantID(ctx, store.DomainsListByTenantIDParams{
		TenantID: tenantID,
		Limit:    params.PageSize,
		Offset:   params.Offset,
	})
	if err != nil {
		return DomainsListResult{}, fmt.Errorf("domains list: %w", err)
	}
	var total int64
	if len(rows) > 0 {
		total = rows[0].TotalCount
	}
	return DomainsListResult{
		Domains:    dto.DomainsListByTenantIDToDomains(rows),
		TotalCount: total,
	}, nil
}

// DomainFindingSummary is the per-domain aggregate of open security findings,
// used for list-row badges and the detail findings count. SeverityRank encodes
// the worst open severity: critical=1 high=2 medium=3 low=4 info=5 none=6.
type DomainFindingSummary struct {
	SeverityRank int32
	Count        int32
}

// FindingsSummaryForPage returns the open-findings aggregate keyed by domain ID
// for a whole page of domains in a single query (no N+1). Callers must pass IDs
// they own; the IDs here come from a tenant-scoped List, so results are already
// tenant-bounded.
func (s *DomainsService) FindingsSummaryForPage(
	ctx context.Context,
	_ *auth.Principal,
	domainIDs []int32,
) (map[int32]DomainFindingSummary, error) {
	out := make(map[int32]DomainFindingSummary, len(domainIDs))
	if len(domainIDs) == 0 {
		return out, nil
	}
	rows, err := s.DB.DomainsListFindingsSummary(ctx, domainIDs)
	if err != nil {
		return nil, fmt.Errorf("findings summary: %w", err)
	}
	for _, row := range rows {
		out[row.DomainID] = DomainFindingSummary{
			SeverityRank: row.SeverityRank,
			Count:        row.FindingCount,
		}
	}
	return out, nil
}

// TenantStats holds the cached tenant-wide rollups shown in the Domains list
// stat strip. Present is false when the refresh job has not yet written a row
// for this tenant (e.g. a brand-new tenant, or before the worker's first run),
// letting handlers fall back to placeholders instead of showing a stale zero.
type TenantStats struct {
	RecordTotal   int64
	CriticalCount int32
	WarningCount  int32
	Present       bool
}

// TenantStats reads the cached stat-strip rollups for the caller's tenant. The
// values are refreshed off the request path by the RefreshTenantStats periodic
// job; a missing row is not an error (Present stays false).
func (s *DomainsService) TenantStats(
	ctx context.Context,
	p *auth.Principal,
) (TenantStats, error) {
	row, err := s.DB.TenantStatsGet(ctx, p.TenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TenantStats{}, nil
		}
		return TenantStats{}, fmt.Errorf("tenant stats: %w", err)
	}
	return TenantStats{
		RecordTotal:   row.RecordTotal,
		CriticalCount: row.CriticalCount,
		WarningCount:  row.WarningCount,
		Present:       true,
	}, nil
}

// RecordCountsForPage returns the DNS record count per domain for a page of
// domain IDs, in a single query (no N+1).
func (s *DomainsService) RecordCountsForPage(
	ctx context.Context,
	_ *auth.Principal,
	domainIDs []int32,
) (map[int32]int32, error) {
	out := make(map[int32]int32, len(domainIDs))
	if len(domainIDs) == 0 {
		return out, nil
	}
	rows, err := s.DB.DomainsListRecordCounts(ctx, domainIDs)
	if err != nil {
		return nil, fmt.Errorf("record counts: %w", err)
	}
	for _, row := range rows {
		out[row.DomainID] = row.RecordCount
	}
	return out, nil
}

// Get returns the domain identified by uid, scoped to the caller's tenant.
// Returns ErrNotFound when the UID does not exist or belongs to another tenant.
func (s *DomainsService) Get(
	ctx context.Context,
	p *auth.Principal,
	uid string,
) (store.Domains, error) {
	row, err := s.DB.DomainsGetByID(ctx, store.DomainsGetByIDParams{
		Uid:      uid,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		return store.Domains{}, ErrNotFound
	}
	return store.Domains{
		ID:         row.ID,
		Uid:        row.Uid,
		TenantID:   row.TenantID,
		Name:       row.Name,
		DomainType: row.DomainType,
		Source:     row.Source,
		Status:     row.Status,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}, nil
}

// Create inserts a new domain and schedules its first scan, all within one
// transaction. A duplicate (tenant_id, name) raises ErrConflict.
//
// Canonicalize before both the insert and (implicitly) the uniqueness check
// so case/trailing-dot variants can't bypass the 409 or split a timeline.
//
// One transaction covers the domain write AND the scan enqueue: if scheduling
// fails, the domain insert rolls back rather than leaving a domain with no scan.
func (s *DomainsService) Create(
	ctx context.Context,
	p *auth.Principal,
	params DomainsCreateParams,
) (store.Domains, error) {
	name := dnsrecords.CanonicalizeDomain(params.Domain)

	status := store.DomainStatusActive
	if params.Status != "" {
		status = store.DomainStatus(params.Status)
	}
	domainSource := store.DomainSourceUserSupplied
	if params.Source != "" {
		domainSource = store.DomainSource(params.Source)
	}
	domainType := store.DomainTypeSubdomain
	if params.DomainType != "" {
		dt, _ := dnsrecords.GetDomainType(name)
		domainType = store.DomainType(dt)
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return store.Domains{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	// Insert-only (vs the enumeration upsert): a duplicate (tenant_id, name) raises
	// a unique-violation we map to ErrConflict. This is TOCTOU-safe against two
	// concurrent duplicate POSTs, unlike a separate GetByName check.
	domain, err := st.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: p.TenantID, Valid: true},
		Name:       name,
		DomainType: domainType,
		Source:     domainSource,
		Status:     status,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return store.Domains{}, ErrConflict
		}
		return store.Domains{}, fmt.Errorf("insert domain: %w", err)
	}

	if _, err := s.scheduler.Schedule(ctx, tx, st, jobs.DomainScanTarget{
		TenantID:   p.TenantID,
		DomainID:   domain.ID,
		DomainUID:  domain.Uid,
		DomainName: domain.Name,
		Status:     domain.Status,
	}, domainSource); err != nil {
		return store.Domains{}, fmt.Errorf("schedule scan: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return store.Domains{}, fmt.Errorf("commit: %w", err)
	}

	return store.Domains{
		ID:         domain.ID,
		Uid:        domain.Uid,
		TenantID:   pgtype.Int4{Int32: p.TenantID, Valid: true},
		Name:       domain.Name,
		DomainType: domain.DomainType,
		Source:     domain.Source,
		Status:     domain.Status,
		CreatedAt:  domain.CreatedAt,
		UpdatedAt:  domain.UpdatedAt,
	}, nil
}

// Update applies partial field patches to an existing domain and forces a rescan.
// Returns ErrNotFound when the domain does not exist in the caller's tenant.
//
// PUT is an explicit user action, like POST: Force bypasses the recency guard
// (a user-triggered rescan always runs) but NOT the active-status gate (an
// inactive domain is still not scanned), and enumeration is requested at the apex.
func (s *DomainsService) Update(
	ctx context.Context,
	p *auth.Principal,
	uid string,
	params DomainsUpdateParams,
) (store.Domains, error) {
	existing, err := s.DB.DomainsGetByID(ctx, store.DomainsGetByIDParams{
		Uid:      uid,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		return store.Domains{}, ErrNotFound
	}

	status := existing.Status
	if params.Status != "" {
		status = store.DomainStatus(params.Status)
	}
	domainSource := existing.Source
	if params.Source != "" {
		domainSource = store.DomainSource(params.Source)
	}
	domainType := existing.DomainType
	if params.DomainType != "" {
		domainType = store.DomainType(params.DomainType)
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return store.Domains{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	domain, err := st.DomainsUpdateByID(ctx, store.DomainsUpdateByIDParams{
		Uid:        uid,
		Status:     status,
		DomainType: domainType,
		Source:     domainSource,
		TenantID:   pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.Log.Error("failed to update domain", "error", err, "uid", uid)
		}
		return store.Domains{}, fmt.Errorf("update domain: %w", err)
	}

	if _, err := s.scheduler.Schedule(ctx, tx, st, jobs.DomainScanTarget{
		TenantID:   domain.TenantID.Int32,
		DomainID:   domain.ID,
		DomainUID:  domain.Uid,
		DomainName: domain.Name,
		Status:     domain.Status,
	}, domainSource); err != nil {
		return store.Domains{}, fmt.Errorf("schedule scan: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return store.Domains{}, fmt.Errorf("commit: %w", err)
	}

	return store.Domains{
		ID:         domain.ID,
		Uid:        domain.Uid,
		TenantID:   domain.TenantID,
		Name:       domain.Name,
		DomainType: domain.DomainType,
		Source:     domain.Source,
		Status:     domain.Status,
		CreatedAt:  domain.CreatedAt,
		UpdatedAt:  domain.UpdatedAt,
	}, nil
}

// Delete removes the domain from the caller's tenant.
// Returns ErrNotFound when the domain does not exist or belongs to another tenant.
func (s *DomainsService) Delete(
	ctx context.Context,
	p *auth.Principal,
	uid string,
) error {
	_, err := s.DB.DomainsDeleteByID(ctx, store.DomainsDeleteByIDParams{
		Uid:      uid,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("delete domain: %w", err)
	}
	return nil
}

// DeletionImpact returns the number of domains that would be deleted (including
// cascaded child domains) if this domain were removed.
//
// The recursive CTE always counts the domain itself, so a count of 0 means the
// domain does not exist in the caller's tenant — 404, consistent with the other
// by-uid paths.
func (s *DomainsService) DeletionImpact(
	ctx context.Context,
	p *auth.Principal,
	uid string,
) (int64, error) {
	count, err := s.DB.DomainsDeleteCount(ctx, store.DomainsDeleteCountParams{
		Uid:      uid,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		s.Log.Error("failed to count domains for deletion", "error", err, "id", uid)
		return 0, fmt.Errorf("deletion impact: %w", err)
	}
	if count == 0 {
		return 0, ErrNotFound
	}
	return count, nil
}
