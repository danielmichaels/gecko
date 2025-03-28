-- name: StoreZoneTransferFinding :exec
INSERT INTO zone_transfer_findings (domain_id,
                                    ns_record_id,
                                    severity,
                                    status,
                                    nameserver,
                                    zone_transfer_possible,
                                    transfer_type,
                                    details,
                                    transfer_details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (domain_id, nameserver)
    DO UPDATE SET ns_record_id           = $2,
                  severity               = $3,
                  status                 = $4,
                  zone_transfer_possible = $6,
                  transfer_type          = $7,
                  details                = $8,
                  transfer_details       = $9;

-- name: AssessCreateSPFFinding :exec
INSERT INTO spf_findings (domain_id,
                          txt_record_id,
                          severity,
                          status,
                          issue_type,
                          spf_value,
                          details)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (domain_id, issue_type)
    DO UPDATE SET txt_record_id = $2,
                  severity      = $3,
                  status        = $4,
                  spf_value     = $6,
                  details       = $7;

-- name: AssessGetSPFFindings :many
SELECT *
FROM spf_findings
WHERE domain_id = $1
ORDER BY severity ASC, created_at DESC;

-- name: AssessGetSPFFindingByDomainID :many
SELECT sf.*
FROM spf_findings sf
         JOIN domains d ON sf.domain_id = d.id
WHERE d.uid = $1
ORDER BY sf.severity ASC, sf.created_at DESC;

-- name: AssessCreateDKIMFinding :exec
INSERT INTO dkim_findings (domain_id,
                           txt_record_id,
                           severity,
                           status,
                           selector,
                           issue_type,
                           dkim_value,
                           details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (domain_id, issue_type, selector)
WHERE selector IS NOT NULL
    DO UPDATE SET txt_record_id = $2,
                  severity      = $3,
                  status        = $4,
                  dkim_value    = $7,
                  details       = $8;
-- name: AssessCreateDKIMFindingNoSelector :exec
INSERT INTO dkim_findings (domain_id,
                           txt_record_id,
                           severity,
                           status,
                           selector,
                           issue_type,
                           dkim_value,
                           details)
VALUES ($1, $2, $3, $4, NULL, $5, $6, $7)
ON CONFLICT (domain_id, issue_type)
    WHERE (selector IS NULL)
    DO UPDATE SET txt_record_id = $2,
                  severity      = $3,
                  status        = $4,
                  dkim_value    = $6,
                  details       = $7;

-- name: AssessGetDKIMFindings :many
SELECT *
FROM dkim_findings
WHERE domain_id = $1
ORDER BY severity ASC, created_at DESC;

-- name: AssessDKIMFindingsByDomainID :many
SELECT df.*
FROM dkim_findings df
         JOIN domains d ON df.domain_id = d.id
WHERE d.uid = $1
ORDER BY df.severity ASC, df.created_at DESC;

-- name: AssessCreateDMARCFinding :exec
INSERT INTO dmarc_findings (domain_id,
                            txt_record_id,
                            severity,
                            status,
                            policy,
                            issue_type,
                            dmarc_value,
                            details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (domain_id, issue_type)
    DO UPDATE SET txt_record_id = $2,
                  severity      = $3,
                  status        = $4,
                  policy        = $5,
                  dmarc_value  = $7,
                  details       = $8;

-- name: AssessGetDMARCFindings :many
SELECT *
FROM dmarc_findings
WHERE domain_id = $1
ORDER BY severity ASC, created_at DESC;

-- name: AssessGetDMARCFindingsByDomainID :many
SELECT df.*
FROM dmarc_findings df
         JOIN domains d ON df.domain_id = d.id
WHERE d.uid = $1
ORDER BY df.severity ASC, df.created_at DESC;

-- name: AssessGetZoneTransferFindings :many
SELECT id, uid, domain_id, ns_record_id, severity, status, nameserver, zone_transfer_possible,
       transfer_type, details, transfer_details, created_at, updated_at
FROM zone_transfer_findings
WHERE domain_id = $1
ORDER BY severity ASC, created_at DESC;

-- name: AssessGetZoneTransferFindingsByDomainUID :many
SELECT ztf.*
FROM zone_transfer_findings ztf
         JOIN domains d ON ztf.domain_id = d.id
WHERE d.uid = $1
ORDER BY ztf.severity ASC, ztf.created_at DESC;
