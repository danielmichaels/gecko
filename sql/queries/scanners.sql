-- name: ScannersStoreZoneTransferAttempt :one
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
                  updated_at     = NOW()
RETURNING (xmax = 0)::boolean AS inserted;
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

-- name: ScannersStoreCertificate :one
INSERT INTO certificates (domain_id,
                          not_before,
                          not_after,
                          issuer,
                          issuer_org_name,
                          issuer_country,
                          subject,
                          key_algorithm,
                          key_strength,
                          sans,
                          dns_names,
                          is_ca,
                          issuer_cert_url,
                          cipher_suite,
                          tls_version)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (domain_id)
    DO UPDATE SET not_before      = $2,
                  not_after       = $3,
                  issuer          = $4,
                  issuer_org_name = $5,
                  issuer_country  = $6,
                  subject         = $7,
                  key_algorithm   = $8,
                  key_strength    = $9,
                  sans            = $10,
                  dns_names       = $11,
                  is_ca           = $12,
                  issuer_cert_url = $13,
                  cipher_suite    = $14,
                  tls_version     = $15,
                  updated_at      = NOW()
RETURNING (xmax = 0)::boolean AS inserted;

-- name: ScannersGetCertificate :one
SELECT *
FROM certificates
WHERE domain_id = $1;

-- name: ScannersStoreDNSSECResult :one
INSERT INTO dnssec_scan_results (domain_id,
                                 status,
                                 validation_error,
                                 has_dnskey,
                                 has_ds,
                                 has_rrsig,
                                 algorithms)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (domain_id)
    DO UPDATE SET status           = $2,
                  validation_error = $3,
                  has_dnskey       = $4,
                  has_ds           = $5,
                  has_rrsig        = $6,
                  algorithms       = $7,
                  updated_at       = NOW()
RETURNING (xmax = 0)::boolean AS inserted;

-- name: ScannersGetDNSSECResult :one
SELECT *
FROM dnssec_scan_results
WHERE domain_id = $1;
