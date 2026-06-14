-- name: UserCreate :one
-- Guarded insert: the acting user ($5) must be manager/owner/superadmin in the
-- target tenant ($1). Retained for in-tenant invite-by-manager flows; signup and
-- accept-invite use UserProvision instead (no acting user exists yet).
INSERT INTO users (tenant_id, email, name, role)
SELECT $1, $2, $3, $4
WHERE EXISTS (SELECT 1
              FROM users u
              WHERE u.id = $5
                AND u.tenant_id = $1
                AND u.role IN ('manager', 'owner', 'superadmin'))
RETURNING *;

-- name: UserProvision :one
-- Unguarded insert for signup (role 'owner') and accept-invite (role from the
-- invite). Authorized by SIGNUP_ENABLED / the invite token, not by an actor.
INSERT INTO users (tenant_id, email, name, role)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: UserGetByEmail :one
SELECT id, uid, tenant_id, email, name, role, status, created_at, updated_at
FROM users
WHERE email = $1;

-- name: UserGetByID :one
SELECT id, uid, tenant_id, email, name, role, status, created_at, updated_at
FROM users
WHERE id = $1;

-- name: UserGetInTenant :one
SELECT id, uid, tenant_id, email, name, role, status, created_at, updated_at
FROM users
WHERE uid = $1
  AND tenant_id = $2;

-- name: UsersCountOwnersInTenant :one
SELECT COUNT(*)
FROM users
WHERE tenant_id = $1
  AND role = 'owner';

-- name: OwnersLockInTenant :many
-- Locks the tenant's owner rows FOR UPDATE so a concurrent transaction cannot remove
-- a different owner between this count and the caller's mutation. The caller treats a
-- result of one row or fewer as "last owner". (FOR UPDATE disallows aggregates, so
-- the rows are returned and counted in Go.)
SELECT id
FROM users
WHERE tenant_id = $1
  AND role = 'owner'
    FOR UPDATE;

-- name: UsersListByTenant :many
SELECT id, uid, tenant_id, email, name, role, status, created_at, updated_at
FROM users
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- name: UsersListDigestRecipientsByTenant :many
-- Recipients of a tenant's daily digest: active owners and managers only. Viewers
-- and non-active (pending/inactive) users are excluded. Ordered by email for a
-- stable fan-out.
SELECT email, name, role
FROM users
WHERE tenant_id = $1
  AND status = 'active'
  AND role IN ('owner', 'manager')
ORDER BY email;

-- name: UserUpdateInTenant :one
-- Keyed by uid (the external identifier). tenant_id is intentionally not settable:
-- a user cannot be re-homed across tenants via update.
UPDATE users
SET email = $3,
    name  = $4,
    role  = $5
WHERE uid = $1
  AND tenant_id = $2
RETURNING *;

-- name: UserDeleteInTenant :one
DELETE
FROM users
WHERE uid = $1
  AND tenant_id = $2
RETURNING id, uid, tenant_id, email;

-- name: TenantCreate :one
INSERT INTO tenants (name)
VALUES ($1)
RETURNING *;

-- name: TenantGetByID :one
SELECT id, uid, name, created_at, updated_at
FROM tenants
WHERE id = $1;
