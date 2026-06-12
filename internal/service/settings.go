package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/jobs"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// SettingsService exposes per-tenant configuration. Today that is the default
// scan cadence; future tenant-scoped settings get a home here too.
type SettingsService struct {
	*Service
}

// GetScanSettings returns the tenant's default scan frequency, falling back to the
// system default (daily) when no settings row exists yet (a brand-new tenant
// before its first write). A missing row is not an error.
func (s *SettingsService) GetScanSettings(
	ctx context.Context,
	p *auth.Principal,
) (store.ScanFrequency, error) {
	row, err := s.DB.TenantSettingsGet(ctx, p.TenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ScanFrequencyDaily, nil
		}
		return "", fmt.Errorf("get tenant settings: %w", err)
	}
	return row.DefaultScanFrequency, nil
}

// SetDefaultScanFrequency sets the tenant default cadence and recomputes the
// scheduling cursor for every inheriting domain (no per-domain override) in one
// transaction, so the settings write and the bulk cursor recompute commit
// atomically. Owner/manager only; ErrInvalidInput for an unknown preset.
//
// Overridden domains are untouched — they keep their explicit cadence — and 'off'
// pauses every inheriting domain (cursor cleared).
func (s *SettingsService) SetDefaultScanFrequency(
	ctx context.Context,
	p *auth.Principal,
	freq store.ScanFrequency,
) error {
	if err := ownerOrManager(p); err != nil {
		return err
	}
	if !jobs.IsKnownFrequency(freq) {
		return msgErr(ErrInvalidInput, "unknown scan frequency")
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	if _, err := st.TenantSettingsUpsert(ctx, store.TenantSettingsUpsertParams{
		TenantID:             p.TenantID,
		DefaultScanFrequency: freq,
	}); err != nil {
		return fmt.Errorf("upsert tenant settings: %w", err)
	}

	baseSecs, isOff := jobs.ScheduleArgs(freq)
	if err := st.DomainsRecomputeNextScanByTenantDefault(
		ctx,
		store.DomainsRecomputeNextScanByTenantDefaultParams{
			IsOff:    isOff,
			BaseSecs: baseSecs,
			TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
		},
	); err != nil {
		return fmt.Errorf("recompute inheriting domains: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
