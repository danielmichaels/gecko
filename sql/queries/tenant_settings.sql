-- name: TenantSettingsGet :one
-- Read a tenant's scan settings. Existing tenants were backfilled with a row; a
-- brand-new tenant has none until first write, so callers treat pgx.ErrNoRows as
-- "use the system default" rather than an error.
SELECT tenant_id, default_scan_frequency, created_at, updated_at
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
