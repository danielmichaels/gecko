-- +goose Up
-- +goose StatementBegin
-- Phase two of the membership migration (00020): role and tenant now live solely
-- on memberships, and no read path consults users.role / users.tenant_id, so the
-- now-dead columns are removed. The user_role enum stays (memberships/invitations
-- use it).
DROP INDEX IF EXISTS idx_user_tenant_id;
ALTER TABLE users
    DROP COLUMN IF EXISTS role;
ALTER TABLE users
    DROP COLUMN IF EXISTS tenant_id;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Restore the columns and rehydrate them from memberships (one row per user; if a
-- user belongs to several tenants, the owner-or-earliest membership wins, matching
-- the pre-split single-tenant assumption).
ALTER TABLE users
    ADD COLUMN tenant_id INTEGER REFERENCES tenants (id) ON DELETE CASCADE;
ALTER TABLE users
    ADD COLUMN role user_role NOT NULL DEFAULT 'viewer';
CREATE INDEX idx_user_tenant_id ON users (tenant_id);

UPDATE users u
SET tenant_id = m.tenant_id,
    role      = m.role
FROM (
    SELECT DISTINCT ON (user_id) user_id, tenant_id, role
    FROM memberships
    ORDER BY user_id, (role = 'owner') DESC, created_at
) m
WHERE m.user_id = u.id;
-- +goose StatementEnd
