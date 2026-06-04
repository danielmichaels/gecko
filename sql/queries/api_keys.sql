-- name: ApiKeyCreate :one
INSERT INTO api_keys (tenant_id, user_id, name, prefix, key_hash, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ApiKeyGetByPrefix :one
-- Returns the key plus the owner's role/status so verification can reject keys
-- belonging to non-active users in a single round-trip.
SELECT k.id,
       k.uid,
       k.tenant_id,
       k.user_id,
       k.name,
       k.prefix,
       k.key_hash,
       k.last_used_at,
       k.expires_at,
       k.revoked_at,
       k.created_at,
       u.email  AS user_email,
       u.role   AS user_role,
       u.status AS user_status
FROM api_keys k
         JOIN users u ON u.id = k.user_id
WHERE k.prefix = $1;

-- name: ApiKeyTouchLastUsed :exec
UPDATE api_keys
SET last_used_at = NOW()
WHERE id = $1;

-- name: ApiKeysListByTenant :many
SELECT id, uid, tenant_id, user_id, name, prefix, last_used_at, expires_at, revoked_at, created_at
FROM api_keys
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- name: ApiKeyRevoke :one
UPDATE api_keys
SET revoked_at = NOW()
WHERE uid = $1
  AND tenant_id = $2
  AND revoked_at IS NULL
RETURNING id, uid, tenant_id, user_id, name, prefix, created_at;
