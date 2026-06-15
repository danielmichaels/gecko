-- name: UserProvisionIdentity :one
-- Creates a tenant-agnostic identity (email + optional name). Tenant and role are
-- carried by memberships, not the user row, so signup/accept-invite insert the
-- identity here and attach a membership separately.
INSERT INTO users (email, name)
VALUES ($1, $2)
RETURNING *;

-- name: UserGetByEmail :one
SELECT id, uid, email, name, status, created_at, updated_at, notify_opt_out
FROM users
WHERE email = $1;

-- name: UserGetByID :one
SELECT id, uid, email, name, status, created_at, updated_at, notify_opt_out
FROM users
WHERE id = $1;

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
