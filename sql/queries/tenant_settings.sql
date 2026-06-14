-- name: TenantSettingsGet :one
-- Read a tenant's scan settings. Existing tenants were backfilled with a row; a
-- brand-new tenant has none until first write, so callers treat pgx.ErrNoRows as
-- "use the system default" rather than an error.
SELECT tenant_id, default_scan_frequency, notify_daily_digest, notify_high_impact,
       notifications_last_digest_at, created_at, updated_at
FROM tenant_settings
WHERE tenant_id = $1;

-- name: TenantSettingsUpsert :one
-- Set a tenant's default scan frequency, creating the row on first write. One row
-- per tenant; updated_at is refreshed by the trigger on UPDATE and stamped here on
-- INSERT.
INSERT INTO tenant_settings (tenant_id, default_scan_frequency)
VALUES ($1, $2)
ON CONFLICT (tenant_id)
    DO UPDATE SET default_scan_frequency = EXCLUDED.default_scan_frequency,
                  updated_at             = now()
RETURNING tenant_id, default_scan_frequency, created_at, updated_at;

-- name: NotificationSettingsGet :one
-- Read a tenant's notification toggles and digest watermark. As with the scan
-- settings, a brand-new tenant may have no row yet; callers treat pgx.ErrNoRows as
-- "use the system defaults" (digest on, high-impact on, never sent).
SELECT tenant_id, notify_daily_digest, notify_high_impact, notifications_last_digest_at
FROM tenant_settings
WHERE tenant_id = $1;

-- name: NotificationSettingsUpsert :one
-- Set a tenant's notification toggles, creating the row on first write. Dedicated
-- to the notify_* columns so this write path and the scan-frequency write path
-- never stomp each other's fields. updated_at is refreshed by the trigger on UPDATE
-- and stamped here on INSERT.
INSERT INTO tenant_settings (tenant_id, notify_daily_digest, notify_high_impact)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id)
    DO UPDATE SET notify_daily_digest = EXCLUDED.notify_daily_digest,
                  notify_high_impact  = EXCLUDED.notify_high_impact,
                  updated_at          = now()
RETURNING tenant_id, notify_daily_digest, notify_high_impact, notifications_last_digest_at;

-- name: TenantsListDigestDue :many
-- Tenants eligible for the daily digest (the master toggle is on). The periodic
-- worker filters out empty windows via the observation aggregate; this query just
-- bounds the fan-out to opted-in tenants and carries each one's watermark and
-- high-impact preference.
SELECT tenant_id, notify_high_impact, notifications_last_digest_at
FROM tenant_settings
WHERE notify_daily_digest = true
ORDER BY tenant_id;

-- name: NotificationDigestAdvanceWatermark :exec
-- Advance a tenant's digest watermark to @sent_at (the 'now' captured at the start
-- of the tick). Called inside the same transaction as the digest enqueues so the
-- window and the send commit atomically: a rollback leaves the watermark unmoved
-- and the window is retried on the next tick.
UPDATE tenant_settings
SET notifications_last_digest_at = @sent_at
WHERE tenant_id = @tenant_id;
