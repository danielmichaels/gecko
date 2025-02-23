-- Create test tenant with UID
INSERT INTO tenants (name, uid)
VALUES ('Test Tenant', 'tenant_00000001');

-- Create users with different roles and UIDs for the tenant
INSERT INTO users (tenant_id, email, name, role, uid)
VALUES
    ((SELECT id FROM tenants LIMIT 1), 'admin@danielms.site', 'Admin User', 'owner', 'user_00000001'),
    ((SELECT id FROM tenants LIMIT 1), 'viewer@danielms.site', 'Viewer User', 'viewer', 'user_00000002')
ON CONFLICT (email) DO NOTHING;

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