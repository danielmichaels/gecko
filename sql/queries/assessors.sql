-- name: StoreZoneTransferFinding :exec
INSERT INTO zone_transfer_findings (
    domain_id,
    ns_record_id,
    severity,
    status,
    nameserver,
    zone_transfer_possible,
    transfer_type,
    details
) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8
         )
ON CONFLICT (domain_id, nameserver)
    DO UPDATE SET
                  ns_record_id = $2,
                  severity = $3,
                  status = $4,
                  zone_transfer_possible = $6,
                  transfer_type = $7,
                  details = $8;
