-- name: ScannersStoreZoneTransferAttempt :exec
INSERT INTO zone_transfer_attempts (domain_id,
                                    nameserver,
                                    transfer_type,
                                    was_successful,
                                    response_data,
                                    error_message)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (domain_id, nameserver)
    DO UPDATE SET transfer_type  = $3,
                  was_successful = $4,
                  response_data  = $5,
                  error_message  = $6,
                  updated_at     = NOW();
-- name: ScannersGetZoneTransferAttempts :many
SELECT id,
       uid,
       domain_id,
       nameserver,
       transfer_type,
       was_successful,
       response_data,
       error_message,
       created_at,
       updated_at
FROM zone_transfer_attempts
WHERE domain_id = $1
ORDER BY updated_at DESC;
