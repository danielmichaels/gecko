-- name: SessionCreate :one
INSERT INTO sessions (user_id, tenant_id, token_hash, expires_at, user_agent, ip)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING uid, expires_at, created_at, last_used_at;

-- name: SessionResolve :one
-- Returns only live sessions (expires_at > NOW()); expired sessions are treated
-- as not-found by callers. The INNER JOIN on memberships sources the role for the
-- session's active tenant and is load-bearing: if the user's membership in that
-- tenant was revoked, the row vanishes and the session is rejected (treated as
-- not-found), so a stale session cannot retain access to a tenant the user left.
SELECT s.user_id,
       s.tenant_id,
       s.token_hash,
       s.expires_at,
       s.last_used_at,
       u.email    AS user_email,
       m.role     AS user_role
FROM sessions s
         JOIN users u ON u.id = s.user_id
         JOIN memberships m ON m.user_id = s.user_id AND m.tenant_id = s.tenant_id
WHERE s.token_hash = $1
  AND s.expires_at > NOW();

-- name: SessionUpdateTenant :exec
-- Switches the active tenant of the current session. Callers MUST validate that
-- the user is a member of the target tenant before calling.
UPDATE sessions
SET tenant_id = $2
WHERE token_hash = $1;

-- name: SessionTouch :exec
UPDATE sessions
SET last_used_at = NOW()
WHERE token_hash = $1;

-- name: SessionRevoke :exec
DELETE
FROM sessions
WHERE token_hash = $1;

-- name: SessionRevokeAllForUser :exec
-- Invalidates every session for a user; called after a password reset so a
-- forgotten/compromised credential cannot survive on an existing session.
DELETE
FROM sessions
WHERE user_id = $1;
