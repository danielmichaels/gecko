-- name: TenantStatsUpsert :exec
-- Cache the periodic-refresh rollups for a tenant. ON CONFLICT keeps a single
-- row per tenant and stamps updated_at on every refresh.
INSERT INTO tenant_stats (tenant_id, record_total, critical_count, warning_count, updated_at)
VALUES ($1, $2, $3, $4, now())
ON CONFLICT (tenant_id) DO UPDATE
    SET record_total   = EXCLUDED.record_total,
        critical_count = EXCLUDED.critical_count,
        warning_count  = EXCLUDED.warning_count,
        updated_at     = now();

-- name: TenantStatsGet :one
-- Read a tenant's cached stat strip. Returns no row when the refresh job has not
-- yet run for this tenant; callers fall back to placeholders.
SELECT tenant_id, record_total, critical_count, warning_count, updated_at
FROM tenant_stats
WHERE tenant_id = $1;
