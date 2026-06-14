-- +goose Up
-- +goose StatementBegin
-- memberships make user↔tenant many-to-many: one identity (users row, globally
-- unique email, single credential) can belong to multiple tenants, each with its
-- own role. role moves OFF users onto the membership; users.role / users.tenant_id
-- are retired in a later migration once no read path consults them.
CREATE TABLE IF NOT EXISTS memberships
(
    id         SERIAL PRIMARY KEY,
    uid        TEXT UNIQUE                 NOT NULL DEFAULT ('mbr_' || generate_uid(8)),
    user_id    INTEGER                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id  INTEGER                     NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    role       user_role                   NOT NULL,
    created_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, tenant_id)
);
CREATE INDEX idx_memberships_user_id ON memberships (user_id);
CREATE INDEX idx_memberships_tenant_id ON memberships (tenant_id);
CREATE TRIGGER trigger_updated_at_memberships
    BEFORE UPDATE
    ON memberships
    FOR EACH ROW
EXECUTE FUNCTION updated_at_trigger();

-- Backfill: every existing user has exactly one tenant_id today, so this is a
-- clean 1:1 projection of the current single-tenant world into memberships.
INSERT INTO memberships (user_id, tenant_id, role)
SELECT id, tenant_id, role
FROM users
WHERE tenant_id IS NOT NULL
ON CONFLICT (user_id, tenant_id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS memberships CASCADE;
-- +goose StatementEnd
