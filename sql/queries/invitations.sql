-- name: InvitationCreate :one
INSERT INTO invitations (tenant_id, email, role, token_hash, invited_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: InvitationGetByTokenHash :one
-- Only returns live, open invites; expired/accepted/revoked (deleted) ones are
-- uniformly rejected as not-found.
SELECT id, uid, tenant_id, email, role, token_hash, invited_by, expires_at, accepted_at, created_at
FROM invitations
WHERE token_hash = $1
  AND accepted_at IS NULL
  AND expires_at > NOW();

-- name: InvitationExpiredDelete :exec
-- Clear any stale expired-but-unaccepted invite for (tenant, email) so it does not
-- wedge the partial unique index when re-inviting.
DELETE
FROM invitations
WHERE tenant_id = $1
  AND email = $2
  AND accepted_at IS NULL
  AND expires_at <= NOW();

-- name: InvitationsListByTenant :many
SELECT id, uid, tenant_id, email, role, invited_by, expires_at, accepted_at, created_at
FROM invitations
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- name: InvitationMarkAccepted :exec
UPDATE invitations
SET accepted_at = NOW()
WHERE id = $1;

-- name: InvitationRevoke :one
-- Hard delete: a revoked invite ceases to exist (no revoked_at column needed).
DELETE
FROM invitations
WHERE uid = $1
  AND tenant_id = $2
  AND accepted_at IS NULL
RETURNING id, uid, tenant_id, email;
