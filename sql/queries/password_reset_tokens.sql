-- name: PasswordResetTokenCreate :one
INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING id, uid, user_id, token_hash, expires_at, created_at;

-- name: PasswordResetTokenGetByHash :one
-- Returns only live, unused tokens; used or expired tokens are treated as
-- not-found by callers so the two cases are indistinguishable to the user.
SELECT id, uid, user_id, token_hash, expires_at, used_at, created_at
FROM password_reset_tokens
WHERE token_hash = $1
  AND used_at IS NULL
  AND expires_at > NOW();

-- name: PasswordResetTokenMarkUsed :exec
UPDATE password_reset_tokens
SET used_at = NOW()
WHERE id = $1;

-- name: PasswordResetTokenPurgeExpired :exec
DELETE
FROM password_reset_tokens
WHERE expires_at < NOW()
   OR used_at IS NOT NULL;
