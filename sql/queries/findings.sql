-- name: FindingsUpsert :one
-- Upsert a finding by its identity key, returning the row id and the status it had
-- BEFORE this call (NULL when newly inserted) so the caller can emit the right
-- lifecycle event. A previously-resolved finding is reopened: status back to open,
-- resolved_at cleared, first_seen preserved.
WITH prior AS (SELECT status
               FROM findings
               WHERE tenant_id = $1
                 AND asset_id = $2
                 AND check_kind = $3
                 AND issue_type = $4
                 AND entity_key = $5)
INSERT INTO findings (tenant_id, asset_id, check_kind, issue_type, entity_key, severity, title, details, evidence)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (tenant_id, asset_id, check_kind, issue_type, entity_key)
    DO UPDATE SET severity    = EXCLUDED.severity,
                  title       = EXCLUDED.title,
                  details     = EXCLUDED.details,
                  evidence    = EXCLUDED.evidence,
                  status      = 'open',
                  resolved_at = NULL,
                  last_seen   = NOW()
RETURNING id, COALESCE((SELECT status FROM prior), '')::text AS prior_status;

-- name: FindingsListOpenByAssetCheck :many
-- The open findings for one asset+check, used to compute which became absent.
SELECT id, issue_type, entity_key
FROM findings
WHERE asset_id = $1
  AND check_kind = $2
  AND status = 'open';

-- name: FindingsResolve :exec
UPDATE findings
SET status      = 'resolved',
    resolved_at = NOW()
WHERE id = $1
  AND status = 'open';

-- name: FindingsEventInsert :exec
INSERT INTO findings_events (finding_id, event)
VALUES ($1, $2);
