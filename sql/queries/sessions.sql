-- name: SessionCreate :one
INSERT INTO sessions (user_id, tenant_id, token_hash, expires_at, user_agent, ip)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING uid, expires_at, created_at, last_used_at;

-- name: SessionResolve :one
-- Returns only live sessions (expires_at > NOW()); expired sessions are treated
-- as not-found by callers.
SELECT s.user_id,
       s.tenant_id,
       s.token_hash,
       s.expires_at,
       s.last_used_at,
       u.email    AS user_email,
       u.role     AS user_role
FROM sessions s
         JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1
  AND s.expires_at > NOW();

-- name: SessionTouch :exec
UPDATE sessions
SET last_used_at = NOW()
WHERE token_hash = $1;

-- name: SessionRevoke :exec
DELETE
FROM sessions
WHERE token_hash = $1;
