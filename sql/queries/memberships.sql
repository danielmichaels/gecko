-- name: MembershipCreate :one
-- Attaches a user to a tenant with a role. A unique violation on
-- (user_id, tenant_id) means the user is already a member of that tenant.
INSERT INTO memberships (user_id, tenant_id, role)
VALUES ($1, $2, $3)
RETURNING *;

-- name: MembershipGetRole :one
-- Hot path for auth resolution and membership checks. pgx.ErrNoRows means the
-- user is not a member of the tenant and the caller must reject.
SELECT role
FROM memberships
WHERE user_id = $1
  AND tenant_id = $2;

-- name: MembershipsListForUser :many
-- All tenants a user belongs to, with their role in each. Powers the UI tenant
-- switcher and login's active-tenant selection.
SELECT t.id   AS tenant_id,
       t.uid  AS tenant_uid,
       t.name AS tenant_name,
       m.role AS role,
       m.created_at
FROM memberships m
         JOIN tenants t ON t.id = m.tenant_id
WHERE m.user_id = $1
ORDER BY t.name;

-- name: MembershipsListByTenant :many
-- Members of a tenant with their per-tenant role. Replaces UsersListByTenant for
-- the team page now that role lives on the membership, not the user row.
SELECT u.id         AS user_id,
       u.uid        AS user_uid,
       u.email,
       u.name,
       u.status,
       m.role,
       m.created_at AS joined_at
FROM memberships m
         JOIN users u ON u.id = m.user_id
WHERE m.tenant_id = $1
ORDER BY m.created_at DESC;

-- name: MembershipGetInTenant :one
-- Resolves a single member (by user uid) within a tenant, returning identity plus
-- per-tenant role. ErrNoRows when the user is not a member of the tenant.
SELECT u.id         AS user_id,
       u.uid        AS user_uid,
       u.email,
       u.name,
       u.status,
       m.role,
       m.id         AS membership_id,
       m.created_at AS joined_at
FROM memberships m
         JOIN users u ON u.id = m.user_id
WHERE u.uid = $1
  AND m.tenant_id = $2;

-- name: MembershipsCountOwnersInTenant :one
SELECT COUNT(*)
FROM memberships
WHERE tenant_id = $1
  AND role = 'owner';

-- name: MembershipOwnersLockInTenant :many
-- Locks the tenant's owner memberships FOR UPDATE so a concurrent transaction
-- cannot remove a different owner between this count and the caller's mutation.
-- The caller treats one row or fewer as "last owner".
SELECT id
FROM memberships
WHERE tenant_id = $1
  AND role = 'owner'
    FOR UPDATE;

-- name: MembershipUpdateRole :one
-- Keyed by user uid + tenant. tenant_id is not settable: a membership cannot be
-- re-homed across tenants via update.
UPDATE memberships m
SET role = $3
FROM users u
WHERE m.user_id = u.id
  AND u.uid = $1
  AND m.tenant_id = $2
RETURNING m.id, m.uid, m.user_id, m.tenant_id, m.role;

-- name: MembershipDelete :one
-- Removes a user from a tenant. The user's identity and memberships in other
-- tenants survive. Keyed by user uid + tenant.
DELETE
FROM memberships m
    USING users u
WHERE m.user_id = u.id
  AND u.uid = $1
  AND m.tenant_id = $2
RETURNING m.id, m.user_id, m.tenant_id;
