package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
)

// NotificationsService exposes the per-tenant notification toggles (the daily digest
// and high-impact switches) and the per-user opt-out. The digest/alert *jobs*
// themselves run as system actors and talk to the store directly; this service is
// the authenticated UI/API path for reading and changing preferences.
type NotificationsService struct {
	*Service
}

// NotificationSettings is the read model for a tenant's notification toggles plus
// the last-sent timestamps (zero when never sent).
type NotificationSettings struct {
	LastDigestAt     time.Time
	LastAlertAt      time.Time
	DailyDigest      bool
	HighImpact       bool
	HighImpactAlerts bool
}

// defaultNotificationSettings is the system default for a tenant with no settings
// row yet: the digest and its high-impact section are opt-out (on); the more
// intrusive real-time alerts are opt-in (off).
var defaultNotificationSettings = NotificationSettings{
	DailyDigest:      true,
	HighImpact:       true,
	HighImpactAlerts: false,
}

// GetNotificationSettings returns the tenant's notification toggles, falling back to
// the system defaults when no settings row exists yet. A missing row is not an
// error — mirrors GetScanSettings.
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
		DailyDigest:      row.NotifyDailyDigest,
		HighImpact:       row.NotifyHighImpact,
		HighImpactAlerts: row.NotifyHighImpactAlerts,
		LastDigestAt:     row.NotificationsLastDigestAt.Time,
		LastAlertAt:      row.NotificationsLastAlertAt.Time,
	}, nil
}

// SetNotificationSettings sets the tenant's notification toggles. Owner/manager only.
// The upsert touches only the notify_* columns, so it never disturbs the tenant's
// scan-frequency setting or the watermarks.
func (s *NotificationsService) SetNotificationSettings(
	ctx context.Context,
	p *auth.Principal,
	settings NotificationSettings,
) error {
	if err := ownerOrManager(p); err != nil {
		return err
	}
	if _, err := s.DB.NotificationSettingsUpsert(ctx, store.NotificationSettingsUpsertParams{
		TenantID:               p.TenantID,
		NotifyDailyDigest:      settings.DailyDigest,
		NotifyHighImpact:       settings.HighImpact,
		NotifyHighImpactAlerts: settings.HighImpactAlerts,
	}); err != nil {
		return fmt.Errorf("upsert notification settings: %w", err)
	}
	return nil
}

// GetMyNotificationOptOut reports whether the caller has personally opted out of all
// notification email. Self-service: it reads the caller's own row.
func (s *NotificationsService) GetMyNotificationOptOut(
	ctx context.Context,
	p *auth.Principal,
) (bool, error) {
	optOut, err := s.DB.UserNotifyOptOutGet(ctx, p.UserID)
	if err != nil {
		return false, fmt.Errorf("get user opt-out: %w", err)
	}
	return optOut, nil
}

// SetMyNotificationOptOut sets the caller's personal notification opt-out. Any
// authenticated user may set their own flag — there is no role gate, because it only
// affects mail addressed to that user.
func (s *NotificationsService) SetMyNotificationOptOut(
	ctx context.Context,
	p *auth.Principal,
	optOut bool,
) error {
	if err := s.DB.UserNotifyOptOutSet(ctx, store.UserNotifyOptOutSetParams{
		UserID: p.UserID,
		OptOut: optOut,
	}); err != nil {
		return fmt.Errorf("set user opt-out: %w", err)
	}
	return nil
}
