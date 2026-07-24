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

type SettingsService struct {
	*Service
}

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
