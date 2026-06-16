-- name: SuppressionsUpsertGlobalRule :one
-- Tenant-global silence rule (domain_id NULL). Idempotent on (tenant, kind,
-- issue_type) via the partial unique index; re-silencing refreshes reason/expiry.
INSERT INTO finding_suppressions (tenant_id, kind, issue_type, state, reason, created_by, expires_at)
VALUES (@tenant_id, @kind, @issue_type, @state, @reason, @created_by, @expires_at)
ON CONFLICT (tenant_id, kind, issue_type) WHERE finding_uid IS NULL AND domain_id IS NULL
    DO UPDATE SET state      = EXCLUDED.state,
                  reason     = EXCLUDED.reason,
                  created_by = EXCLUDED.created_by,
                  expires_at = EXCLUDED.expires_at,
                  updated_at = now()
RETURNING *;

-- name: SuppressionsUpsertDomainRule :one
-- Per-domain silence rule. Idempotent on (domain, kind, issue_type).
INSERT INTO finding_suppressions (tenant_id, domain_id, kind, issue_type, state, reason, created_by,
                                  expires_at)
VALUES (@tenant_id, @domain_id, @kind, @issue_type, @state, @reason, @created_by, @expires_at)
ON CONFLICT (domain_id, kind, issue_type) WHERE finding_uid IS NULL AND domain_id IS NOT NULL
    DO UPDATE SET state      = EXCLUDED.state,
                  reason     = EXCLUDED.reason,
                  created_by = EXCLUDED.created_by,
                  expires_at = EXCLUDED.expires_at,
                  updated_at = now()
RETURNING *;

-- name: SuppressionsUpsertAck :one
-- Per-finding acknowledgement/resolution. Idempotent on the finding uid.
INSERT INTO finding_suppressions (tenant_id, domain_id, finding_uid, state, reason, created_by,
                                  expires_at)
VALUES (@tenant_id, @domain_id, @finding_uid, @state, @reason, @created_by, @expires_at)
ON CONFLICT (finding_uid) WHERE finding_uid IS NOT NULL
    DO UPDATE SET state      = EXCLUDED.state,
                  domain_id  = EXCLUDED.domain_id,
                  reason     = EXCLUDED.reason,
                  created_by = EXCLUDED.created_by,
                  expires_at = EXCLUDED.expires_at,
                  updated_at = now()
RETURNING *;

-- name: SuppressionsListByTenant :many
-- Management view: every rule and ack for the tenant, with the scoped domain (if
-- any) and the creating user's email for display. Newest first.
SELECT fs.*,
       d.uid   AS domain_uid,
       d.name  AS domain_name,
       u.email AS created_by_email
FROM finding_suppressions fs
         LEFT JOIN domains d ON fs.domain_id = d.id
         LEFT JOIN users u ON fs.created_by = u.id
WHERE fs.tenant_id = @tenant_id
ORDER BY fs.created_at DESC;

-- name: SuppressionsListActiveByDomain :many
-- All active (non-expired) suppressions that could apply to one domain: the
-- tenant-global rules (domain_id NULL) plus this domain's own rules and acks.
-- Drives the Go-side read-time annotation in FindingsService.ListByDomain.
SELECT *
FROM finding_suppressions
WHERE tenant_id = @tenant_id
  AND (domain_id IS NULL OR domain_id = @domain_id)
  AND (expires_at IS NULL OR expires_at > now());

-- name: SuppressionsGetByUID :one
SELECT *
FROM finding_suppressions
WHERE uid = @uid
  AND tenant_id = @tenant_id;

-- name: SuppressionsDeleteByUID :one
-- Tenant-scoped delete of a rule or ack; RETURNING lets the caller emit an
-- observation and distinguish not-found (no row) from success.
DELETE
FROM finding_suppressions
WHERE uid = @uid
  AND tenant_id = @tenant_id
RETURNING *;

-- name: SuppressionsDeleteAckByFindingUID :one
-- Un-acknowledge: drop the ack for one finding, tenant-scoped.
DELETE
FROM finding_suppressions
WHERE finding_uid = @finding_uid
  AND tenant_id = @tenant_id
RETURNING *;

-- name: FindingResolveByUID :one
-- Resolve an arbitrary finding uid to its domain identity + canonical kind/issue
-- type, gated to the caller's tenant (the domains join is the security boundary).
-- The kind literals MUST match FindingsListByTenant exactly so a rule created from
-- one surface matches at read time on the others. Used by AcknowledgeFinding.
SELECT sf.uid AS finding_uid, d.id AS domain_id, d.uid AS domain_uid, d.name AS domain_name,
       'SPF'::text AS kind, sf.issue_type AS issue_type
FROM spf_findings sf JOIN domains d ON sf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND sf.uid = @target_uid
UNION ALL
SELECT df.uid, d.id, d.uid, d.name, 'DKIM'::text, df.issue_type
FROM dkim_findings df JOIN domains d ON df.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND df.uid = @target_uid
UNION ALL
SELECT mf.uid, d.id, d.uid, d.name, 'DMARC'::text, mf.issue_type
FROM dmarc_findings mf JOIN domains d ON mf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND mf.uid = @target_uid
UNION ALL
SELECT zf.uid, d.id, d.uid, d.name, 'ZONE'::text,
       CASE WHEN zf.zone_transfer_possible THEN 'zone_transfer_exposed' ELSE 'zone_transfer_refused' END
FROM zone_transfer_findings zf JOIN domains d ON zf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND zf.uid = @target_uid
UNION ALL
SELECT cf.uid, d.id, d.uid, d.name, 'CERT'::text, cf.issue_type
FROM certificate_findings cf JOIN domains d ON cf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND cf.uid = @target_uid
UNION ALL
SELECT nf.uid, d.id, d.uid, d.name, 'DNSSEC'::text, nf.issue_type
FROM dnssec_findings nf JOIN domains d ON nf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND nf.uid = @target_uid
UNION ALL
SELECT dcf.uid, d.id, d.uid, d.name, 'DANGLING'::text,
       CASE WHEN dcf.takeover_possible THEN 'subdomain_takeover' ELSE 'dangling_cname' END
FROM dangling_cname_findings dcf JOIN domains d ON dcf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND dcf.uid = @target_uid
UNION ALL
SELECT crf.uid, d.id, d.uid, d.name, 'CNAME'::text, crf.issue_type
FROM cname_redirection_findings crf JOIN domains d ON crf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND crf.uid = @target_uid
UNION ALL
SELECT ccf.uid, d.id, d.uid, d.name, 'CAA_CONFIG'::text, ccf.issue_type
FROM caa_configuration_findings ccf JOIN domains d ON ccf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND ccf.uid = @target_uid
UNION ALL
SELECT cpf.uid, d.id, d.uid, d.name, 'CAA_COMPLIANCE'::text, cpf.issue_type
FROM caa_compliance_findings cpf JOIN domains d ON cpf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND cpf.uid = @target_uid
UNION ALL
SELECT mrf.uid, d.id, d.uid, d.name, 'MIN_RECORDS'::text, mrf.issue_type
FROM minimum_record_set_findings mrf JOIN domains d ON mrf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND mrf.uid = @target_uid
UNION ALL
SELECT eacf.uid, d.id, d.uid, d.name, 'EMAIL_COMPLIANCE'::text, eacf.issue_type
FROM email_auth_compliance_findings eacf JOIN domains d ON eacf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND eacf.uid = @target_uid
UNION ALL
SELECT ncf.uid, d.id, d.uid, d.name, 'NS_CONFIG'::text, ncf.issue_type
FROM ns_configuration_findings ncf JOIN domains d ON ncf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND ncf.uid = @target_uid
UNION ALL
SELECT nrf.uid, d.id, d.uid, d.name, 'NS_REDUNDANCY'::text, nrf.issue_type
FROM nameserver_redundancy_findings nrf JOIN domains d ON nrf.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND nrf.uid = @target_uid
UNION ALL
SELECT rch.uid, d.id, d.uid, d.name, 'NS_REACHABILITY'::text, rch.issue_type
FROM nameserver_reachability_findings rch JOIN domains d ON rch.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND rch.uid = @target_uid
UNION ALL
SELECT lat.uid, d.id, d.uid, d.name, 'NS_LATENCY'::text, 'high_latency'::text
FROM dns_resolution_latency_findings lat JOIN domains d ON lat.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND lat.uid = @target_uid
UNION ALL
SELECT con.uid, d.id, d.uid, d.name, 'NS_CONSISTENCY'::text, 'resolver_mismatch'::text
FROM dns_resolution_consistency_findings con JOIN domains d ON con.domain_id = d.id
WHERE d.tenant_id = @tenant_id AND con.uid = @target_uid
LIMIT 1;
