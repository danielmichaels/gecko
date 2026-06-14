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

-- name: UserProvisionIdentity :one
-- Creates a tenant-agnostic identity (email + optional name). Tenant and role are
-- carried by memberships, not the user row, so signup/accept-invite insert the
-- identity here and attach a membership separately. users.tenant_id/role are left
-- at their defaults (NULL / 'viewer') and are not consulted by any read path.
INSERT INTO users (email, name)
VALUES ($1, $2)
RETURNING *;

-- name: UserGetByEmail :one
SELECT id, uid, tenant_id, email, name, role, status, created_at, updated_at, notify_opt_out
FROM users
WHERE email = $1;

-- name: UserGetByID :one
SELECT id, uid, tenant_id, email, name, role, status, created_at, updated_at, notify_opt_out
FROM users
WHERE id = $1;

-- name: UserGetInTenant :one
SELECT id, uid, tenant_id, email, name, role, status, created_at, updated_at, notify_opt_out
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
SELECT id, uid, tenant_id, email, name, role, status, created_at, updated_at, notify_opt_out
FROM users
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- name: UsersListDigestRecipientsByTenant :many
-- Recipients of a tenant's daily digest: active owners/managers in the tenant who
-- have not personally opted out. Role and tenant come from memberships (users.role
-- /tenant_id are retired); viewers and non-active users are excluded. Ordered by
-- email for a stable fan-out.
SELECT u.email, u.name, m.role
FROM users u
         JOIN memberships m ON m.user_id = u.id
WHERE m.tenant_id = $1
  AND u.status = 'active'
  AND m.role IN ('owner', 'manager')
  AND u.notify_opt_out = false
ORDER BY u.email;

-- name: UserNotifyOptOutGet :one
-- Read a single user's personal notification opt-out flag.
SELECT notify_opt_out
FROM users
WHERE id = $1;

-- name: UserNotifyOptOutSet :exec
-- Set a user's personal notification opt-out. Self-service: the caller sets their
-- own flag, so this is keyed on the user id with no role gate.
UPDATE users
SET notify_opt_out = @opt_out,
    updated_at     = now()
WHERE id = @user_id;

-- name: UserUpdateIdentity :one
-- Updates the tenant-agnostic identity (email, name) by uid. Authorization is the
-- caller's: a tenant admin may edit a member's identity, having already confirmed
-- membership. Role is per-tenant and changed via MembershipUpdateRole instead.
UPDATE users
SET email = $2,
    name  = $3
WHERE uid = $1
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

-- name: TenantGetByUID :one
SELECT id, uid, name, created_at, updated_at
FROM tenants
WHERE uid = $1;
