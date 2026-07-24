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

type NotificationsService struct {
	*Service
}

type NotificationSettings struct {
	LastDigestAt     time.Time
	LastAlertAt      time.Time
	DailyDigest      bool
	HighImpact       bool
	HighImpactAlerts bool
}

var defaultNotificationSettings = NotificationSettings{
	DailyDigest:      true,
	HighImpact:       true,
	HighImpactAlerts: false,
}

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
