-- Create a new user (only allowed for 'manager' and 'owner')
-- name: CreateUser :one
INSERT INTO users (tenant_id, email, name, role)
SELECT $1, $2, $3, $4
WHERE EXISTS (SELECT 1
              FROM users u
              WHERE u.id = $5
                AND u.role IN ('manager', 'owner'))
RETURNING *;

-- Read a user by ID (superadmin can see all, others can see within their tenant)
-- name: GetUserByID :one
SELECT *
FROM users u
WHERE (id = $1 AND u.role = 'superadmin')
   OR (id = $1 AND u.tenant_id = $2);

-- Read all users (superadmin can see all, others can see within their tenant)
-- name: GetUsers :many
SELECT *
FROM users u
WHERE u.role = 'superadmin'
   OR u.tenant_id = $1;

-- Update a user by ID (only allowed for 'manager' and 'owner' within their tenant)
-- name: UpdateUser :one
UPDATE users u
SET tenant_id = $2,
    email     = $3,
    name      = $4,
    role      = $5
WHERE u.id = $1
  AND EXISTS (SELECT 1
              FROM users auth
              WHERE auth.id = $6
                AND auth.role IN ('manager', 'owner')
                AND auth.tenant_id = $2)
RETURNING *;

-- Delete a user by ID (only allowed for 'manager' and 'owner' within their tenant)
-- name: DeleteUser :one
DELETE
FROM users u
WHERE u.id = $1
  AND EXISTS (SELECT 1
              FROM users auth
              WHERE auth.id = $2
                AND auth.role IN ('manager', 'owner')
                AND auth.tenant_id = $3)
RETURNING *;
