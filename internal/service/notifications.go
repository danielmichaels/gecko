package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
)

// NotificationsService exposes the per-tenant notification toggles (the daily digest
// and high-impact switches). The digest *job* itself runs as a system actor and
// talks to the store directly; this service is the authenticated UI/API path for
// reading and changing the toggles.
type NotificationsService struct {
	*Service
}

// NotificationSettings is the read model for a tenant's notification toggles.
type NotificationSettings struct {
	DailyDigest bool
	HighImpact  bool
}

// defaultNotificationSettings is the system default for a tenant with no settings
// row yet (opt-out model: both on).
var defaultNotificationSettings = NotificationSettings{DailyDigest: true, HighImpact: true}

// GetNotificationSettings returns the tenant's notification toggles, falling back to
// the system defaults (both on) when no settings row exists yet. A missing row is
// not an error — mirrors GetScanSettings.
func (s *NotificationsService) GetNotificationSettings(
	ctx context.Context,
	p *auth.Principal,
) (NotificationSettings, error) {
	row, err := s.DB.NotificationSettingsGet(ctx, p.TenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return defaultNotificationSettings, nil
		}
		return NotificationSettings{}, fmt.Errorf("get notification settings: %w", err)
	}
	return NotificationSettings{
		DailyDigest: row.NotifyDailyDigest,
		HighImpact:  row.NotifyHighImpact,
	}, nil
}

// SetNotificationSettings sets the tenant's notification toggles. Owner/manager only.
// The upsert touches only the notify_* columns, so it never disturbs the tenant's
// scan-frequency setting or its digest watermark.
func (s *NotificationsService) SetNotificationSettings(
	ctx context.Context,
	p *auth.Principal,
	settings NotificationSettings,
) error {
	if err := ownerOrManager(p); err != nil {
		return err
	}
	if _, err := s.DB.NotificationSettingsUpsert(ctx, store.NotificationSettingsUpsertParams{
		TenantID:          p.TenantID,
		NotifyDailyDigest: settings.DailyDigest,
		NotifyHighImpact:  settings.HighImpact,
	}); err != nil {
		return fmt.Errorf("upsert notification settings: %w", err)
	}
	return nil
}
