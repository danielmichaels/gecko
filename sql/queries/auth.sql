-- name: UserCredentialUpsert :exec
INSERT INTO user_credentials (user_id, password_hash)
VALUES ($1, $2)
ON CONFLICT (user_id)
    DO UPDATE SET password_hash = EXCLUDED.password_hash,
                  updated_at    = NOW();

-- name: UserCredentialGetByUserID :one
SELECT id, user_id, password_hash, created_at, updated_at
FROM user_credentials
WHERE user_id = $1;
