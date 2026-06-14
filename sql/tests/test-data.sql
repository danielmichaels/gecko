-- Create test tenant with UID
INSERT INTO tenants (name, uid)
VALUES ('Test Tenant', 'tenant_00000001');

-- Create users as tenant-agnostic identities (role/tenant now live on memberships)
INSERT INTO users (email, name, uid)
VALUES
    ('admin@danielms.site', 'Admin User', 'user_00000001'),
    ('viewer@danielms.site', 'Viewer User', 'user_00000002')
ON CONFLICT (email) DO NOTHING;

-- Attach the identities to the first tenant with their roles via memberships
INSERT INTO memberships (user_id, tenant_id, role)
SELECT u.id, (SELECT id FROM tenants WHERE uid = 'tenant_00000001'), seed.role
FROM (VALUES
    ('admin@danielms.site', 'owner'::user_role),
    ('viewer@danielms.site', 'viewer'::user_role)
) AS seed(email, role)
         JOIN users u ON u.email = seed.email
ON CONFLICT (user_id, tenant_id) DO NOTHING;

-- Add domains using CTE
WITH domain_data (id, name) AS (
    VALUES (1, 'danielms.site')
)
INSERT INTO domains (tenant_id, name, domain_type, source, status, uid)
SELECT
    (SELECT id FROM tenants LIMIT 1),
    d.name,
    'tld',
    'user_supplied',
    'active',
    'domain_' || LPAD(d.id::text, 8, '0')
FROM domain_data d
ON CONFLICT (tenant_id, name) DO NOTHING;

-- Second tenant to exercise multi-tenant code paths (issue #28)
INSERT INTO tenants (name, uid)
VALUES ('Test Tenant Two', 'tenant_00000002');

WITH domain_data (id, name) AS (
    VALUES (2, 'example-two.test')
)
INSERT INTO domains (tenant_id, name, domain_type, source, status, uid)
SELECT
    (SELECT id FROM tenants WHERE uid = 'tenant_00000002'),
    d.name,
    'tld',
    'user_supplied',
    'active',
    'domain_' || LPAD(d.id::text, 8, '0')
FROM domain_data d
ON CONFLICT (tenant_id, name) DO NOTHING;