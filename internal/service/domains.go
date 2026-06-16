package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/danielmichaels/gecko/internal/jobs"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// DomainsService exposes domain CRUD business logic.
type DomainsService struct {
	*Service
}

// DomainsListParams carries pagination and optional filters for List. Source and
// DomainType are validated against the domain_source / domain_type enums: an empty
// string means "no filter" and an unknown value yields ErrInvalidInput.
type DomainsListParams struct {
	FilterName string
	Source     string
	DomainType string
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

// List returns a tenant-scoped page of domains with optional name/source/
// domain_type filters. Each filter is independently optional (NULL = no filter)
// and resolved into one DomainsList query. An unknown source/domain_type value is
// rejected with ErrInvalidInput before the query runs.
func (s *DomainsService) List(
	ctx context.Context,
	p *auth.Principal,
	params DomainsListParams,
) (DomainsListResult, error) {
	source, err := toNullDomainSource(params.Source)
	if err != nil {
		return DomainsListResult{}, err
	}
	domainType, err := toNullDomainType(params.DomainType)
	if err != nil {
		return DomainsListResult{}, err
	}

	var name pgtype.Text
	if params.FilterName != "" {
		name = pgtype.Text{String: params.FilterName, Valid: true}
	}

	rows, err := s.DB.DomainsList(ctx, store.DomainsListParams{
		TenantID:   pgtype.Int4{Int32: p.TenantID, Valid: true},
		Name:       name,
		Source:     source,
		DomainType: domainType,
		PageLimit:  params.PageSize,
		PageOffset: params.Offset,
	})
	if err != nil {
		return DomainsListResult{}, fmt.Errorf("domains list: %w", err)
	}
	var total int64
	if len(rows) > 0 {
		total = rows[0].TotalCount
	}
	return DomainsListResult{
		Domains:    dto.DomainsListRowToDomains(rows),
		TotalCount: total,
	}, nil
}

// toNullDomainSource validates an optional source filter against the domain_source
// enum: "" means no filter, a known value is applied, anything else is rejected
// with ErrInvalidInput so a typo can't silently widen the result set.
func toNullDomainSource(s string) (store.NullDomainSource, error) {
	if s == "" {
		return store.NullDomainSource{}, nil
	}
	switch store.DomainSource(s) {
	case store.DomainSourceUserSupplied, store.DomainSourceDiscovered:
		return store.NullDomainSource{DomainSource: store.DomainSource(s), Valid: true}, nil
	default:
		return store.NullDomainSource{}, fmt.Errorf("%w: source %q", ErrInvalidInput, s)
	}
}

// toNullDomainType validates an optional domain_type filter against the domain_type
// enum, with the same "" = no filter / unknown = ErrInvalidInput contract.
func toNullDomainType(s string) (store.NullDomainType, error) {
	if s == "" {
		return store.NullDomainType{}, nil
	}
	switch store.DomainType(s) {
	case store.DomainTypeTld, store.DomainTypeSubdomain, store.DomainTypeWildcard,
		store.DomainTypeOld, store.DomainTypeOther:
		return store.NullDomainType{DomainType: store.DomainType(s), Valid: true}, nil
	default:
		return store.NullDomainType{}, fmt.Errorf("%w: domain_type %q", ErrInvalidInput, s)
	}
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
	p *auth.Principal,
	domainIDs []int32,
) (map[int32]DomainFindingSummary, error) {
	out := make(map[int32]DomainFindingSummary, len(domainIDs))
	if len(domainIDs) == 0 {
		return out, nil
	}
	rows, err := s.DB.DomainsListFindingsSummary(ctx, store.DomainsListFindingsSummaryParams{
		TenantID:  p.TenantID,
		DomainIds: domainIDs,
	})
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
		ID:            row.ID,
		Uid:           row.Uid,
		TenantID:      row.TenantID,
		Name:          row.Name,
		DomainType:    row.DomainType,
		Source:        row.Source,
		Status:        row.Status,
		ScanFrequency: row.ScanFrequency,
		NextScanAt:    row.NextScanAt,
		LastScannedAt: row.LastScannedAt,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
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
	if err := ownerOrManager(p); err != nil {
		return store.Domains{}, err
	}
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

	// Signal live streams so the new domain appears on other open sessions
	// immediately, not only once its first scan observation lands.
	observer.NotifyDomainLifecycle(
		ctx, st, p.TenantID, domain.ID, domain.Uid, domain.Name, observer.ChangeCreated,
	)

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
	if err := ownerOrManager(p); err != nil {
		return store.Domains{}, err
	}
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

	// Signal live streams: a status change is list-visible but writes no
	// observation, and an inactive domain is never rescanned to produce one.
	observer.NotifyDomainLifecycle(
		ctx, st, p.TenantID, domain.ID, domain.Uid, domain.Name, observer.ChangeUpdated,
	)

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

// SetScanFrequency sets a domain's per-domain cadence override and recomputes its
// scheduling cursor. freq == nil clears the override so the domain inherits the
// tenant default. Owner/manager only (a cadence change is a mutation, like the
// other domain mutations). Returns ErrInvalidInput for an unknown preset and
// ErrNotFound when the uid is unknown or belongs to another tenant.
//
// The effective frequency (override ?? tenant default) drives the interval; 'off'
// clears the cursor (next_scan_at NULL) so the domain leaves the schedule.
func (s *DomainsService) SetScanFrequency(
	ctx context.Context,
	p *auth.Principal,
	uid string,
	freq *store.ScanFrequency,
) (store.Domains, error) {
	if err := ownerOrManager(p); err != nil {
		return store.Domains{}, err
	}

	var override store.NullScanFrequency
	if freq != nil {
		if !jobs.IsKnownFrequency(*freq) {
			return store.Domains{}, msgErr(ErrInvalidInput, "unknown scan frequency")
		}
		override = store.NullScanFrequency{ScanFrequency: *freq, Valid: true}
	}

	effective := jobs.EffectiveFrequency(override, s.tenantDefault(ctx, p.TenantID))
	baseSecs, isOff := jobs.ScheduleArgs(effective)

	row, err := s.DB.DomainsSetScanFrequency(ctx, store.DomainsSetScanFrequencyParams{
		ScanFrequency: override,
		IsOff:         isOff,
		BaseSecs:      baseSecs,
		Uid:           uid,
		TenantID:      pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return store.Domains{}, ErrNotFound
		}
		return store.Domains{}, fmt.Errorf("set scan frequency: %w", err)
	}

	return store.Domains{
		ID:            row.ID,
		Uid:           row.Uid,
		TenantID:      row.TenantID,
		Name:          row.Name,
		DomainType:    row.DomainType,
		Source:        row.Source,
		Status:        row.Status,
		ScanFrequency: row.ScanFrequency,
		NextScanAt:    row.NextScanAt,
		LastScannedAt: row.LastScannedAt,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}, nil
}

// tenantDefault returns the tenant's default scan frequency, falling back to the
// system default (daily) when no settings row exists yet — the same fallback the
// scheduling queries use, so the Go and SQL resolutions agree.
func (s *DomainsService) tenantDefault(ctx context.Context, tenantID int32) store.ScanFrequency {
	row, err := s.DB.TenantSettingsGet(ctx, tenantID)
	if err != nil {
		return store.ScanFrequencyDaily
	}
	return row.DefaultScanFrequency
}

// Delete removes the domain from the caller's tenant.
// Returns ErrNotFound when the domain does not exist or belongs to another tenant.
func (s *DomainsService) Delete(
	ctx context.Context,
	p *auth.Principal,
	uid string,
) error {
	if err := ownerOrManager(p); err != nil {
		return err
	}
	deleted, err := s.DB.DomainsDeleteByID(ctx, store.DomainsDeleteByIDParams{
		Uid:      uid,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("delete domain: %w", err)
	}

	// A delete writes no observation, so without an explicit signal live browser
	// streams would not see the row (and any cascaded children) disappear until a
	// reload. One tenant-scoped nudge refreshes the whole list.
	observer.NotifyDomainLifecycle(
		ctx, s.DB, p.TenantID, deleted.ID, deleted.Uid, deleted.Name, observer.ChangeDeleted,
	)

	// The delete cascaded away this domain's records/findings, so the tenant's
	// cached counts (possibly now zero) are stale. Enqueue an immediate per-tenant
	// refresh — this is the one change the periodic recompute can't self-heal. A
	// failure here is non-fatal: the periodic job is the backstop.
	if s.statsRefresher != nil {
		if rErr := s.statsRefresher.RefreshTenantStats(ctx, p.TenantID); rErr != nil {
			s.Log.WarnContext(
				ctx,
				"enqueue tenant stats refresh",
				"error",
				rErr,
				"tenant",
				p.TenantID,
			)
		}
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
