-- name: AssetsUpsertDomain :one
-- Ensure the asset row for a domain exists (1:1), bumping last_seen. Idempotent
-- so domains created after the backfill self-register on their first scan.
INSERT INTO assets (tenant_id, kind, value, source, last_seen)
VALUES ($1, 'domain', $2, $3, NOW())
ON CONFLICT (tenant_id, kind, value)
    DO UPDATE SET last_seen = NOW()
RETURNING *;

-- name: AssetsGetByDomainName :one
SELECT *
FROM assets
WHERE tenant_id = $1
  AND kind = 'domain'
  AND value = $2;

-- name: AssetsGetByID :one
SELECT *
FROM assets
WHERE id = $1;
