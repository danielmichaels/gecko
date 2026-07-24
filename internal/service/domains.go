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

type DomainsService struct {
	*Service
}

type DomainsListParams struct {
	FilterName string
	Source     string
	DomainType string
	PageSize   int32
	Offset     int32
}

type DomainsListResult struct {
	Domains    []store.Domains
	TotalCount int64
}

type DomainsCreateParams struct {
	Domain     string
	DomainType string
	Source     string
	Status     string
}

type DomainsUpdateParams struct {
	DomainType string
	Source     string
	Status     string
}

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

type DomainFindingSummary struct {
	SeverityRank int32
	Count        int32
}

func (s *DomainsService) FindingsSummaryForPage(
	ctx context.Context,
	_ *auth.Principal,
	domainIDs []int32,
) (map[int32]DomainFindingSummary, error) {
	out := make(map[int32]DomainFindingSummary, len(domainIDs))
	if len(domainIDs) == 0 {
		return out, nil
	}
	rows, err := s.DB.FindingsSummaryByDomainIDs(ctx, domainIDs)
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

type TenantStats struct {
	RecordTotal   int64
	CriticalCount int32
	WarningCount  int32
	Present       bool
}

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

func (s *DomainsService) tenantDefault(ctx context.Context, tenantID int32) store.ScanFrequency {
	row, err := s.DB.TenantSettingsGet(ctx, tenantID)
	if err != nil {
		return store.ScanFrequencyDaily
	}
	return row.DefaultScanFrequency
}

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

	observer.NotifyDomainLifecycle(
		ctx, s.DB, p.TenantID, deleted.ID, deleted.Uid, deleted.Name, observer.ChangeDeleted,
	)

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
