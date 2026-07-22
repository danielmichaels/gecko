-- Gecko development demo seed.
--
-- Loaded once by `gecko serve` against an EMPTY embedded-Postgres database
-- (POSTGRES_EMBEDDED=true, SEED_ON_STARTUP=true), BEFORE owner auto-bootstrap.
-- Ordering matters: bootstrapOwner adopts the lowest-id tenant, so seeding this
-- tenant first means the bootstrapped owner lands on a populated Domains view.
--
-- Idempotent: the tenant insert is guarded by NOT EXISTS and the domains by
-- ON CONFLICT, so a stray re-run cannot duplicate rows.

INSERT INTO tenants (name, uid)
SELECT 'Gecko Demo', 'tenant_demo00001'
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE uid = 'tenant_demo00001');

WITH demo AS (SELECT id FROM tenants WHERE uid = 'tenant_demo00001')
INSERT INTO domains (tenant_id, name, domain_type, source, status, uid)
SELECT
    demo.id,
    d.name,
    'tld',
    'user_supplied',
    'active',
    'domain_demo' || LPAD(d.n::text, 5, '0')
FROM demo,
     (VALUES (1, 'example.com'), (2, 'iana.org'), (3, 'cloudflare.com')) AS d(n, name)
ON CONFLICT (tenant_id, name) DO NOTHING;
