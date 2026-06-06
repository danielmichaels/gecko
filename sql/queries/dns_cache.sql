-- name: DNSCacheGet :one
SELECT answers, status, expires_at
FROM dns_cache
WHERE qtype = $1
  AND fqdn = $2
  AND expires_at > now();

-- name: DNSCacheUpsert :exec
INSERT INTO dns_cache (qtype, fqdn, answers, status, expires_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (qtype, fqdn) DO UPDATE
    SET answers    = EXCLUDED.answers,
        status     = EXCLUDED.status,
        expires_at = EXCLUDED.expires_at;

-- name: DNSCachePurgeExpired :execrows
DELETE FROM dns_cache
WHERE expires_at < now();

-- name: RateLimitUpsertBucket :exec
INSERT INTO dns_rate_limit_bucket (key, tokens, rate_qps, burst)
VALUES ($1, $2, $3, $4)
ON CONFLICT (key) DO NOTHING;

-- name: RateLimitAcquire :one
UPDATE dns_rate_limit_bucket
SET tokens      = LEAST(burst, tokens + EXTRACT(EPOCH FROM (now() - last_refill)) * rate_qps) - 1,
    last_refill = now(),
    updated_at  = now()
WHERE key = $1
  AND LEAST(burst, tokens + EXTRACT(EPOCH FROM (now() - last_refill)) * rate_qps) >= 1
RETURNING tokens;
