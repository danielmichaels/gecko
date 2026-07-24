-- name: AssetsUpsertDomain :one
-- Ensure the asset row for a domain exists (1:1), bumping last_seen and keeping the
-- domain_id FK current. Idempotent so domains created after the backfill
-- self-register on their first scan; the FK re-link heals any pre-FK asset row.
INSERT INTO assets (tenant_id, kind, value, source, domain_id, last_seen)
VALUES ($1, 'domain', $2, $3, $4, NOW())
ON CONFLICT (tenant_id, kind, value)
    DO UPDATE SET last_seen = NOW(), domain_id = EXCLUDED.domain_id
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
