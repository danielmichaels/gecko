// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: users.sql

package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (tenant_id, email, name, role)
SELECT $1, $2, $3, $4
WHERE EXISTS (SELECT 1
              FROM users u
              WHERE u.id = $5
                AND u.role IN ('manager', 'owner'))
RETURNING id, uid, tenant_id, email, name, role, created_at, updated_at
`

type CreateUserParams struct {
	TenantID pgtype.Int4 `json:"tenant_id"`
	Email    string      `json:"email"`
	Name     pgtype.Text `json:"name"`
	Role     UserRole    `json:"role"`
	ID       int32       `json:"id"`
}

// Create a new user (only allowed for 'manager' and 'owner')
func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (Users, error) {
	row := q.db.QueryRow(ctx, createUser,
		arg.TenantID,
		arg.Email,
		arg.Name,
		arg.Role,
		arg.ID,
	)
	var i Users
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.TenantID,
		&i.Email,
		&i.Name,
		&i.Role,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const deleteUser = `-- name: DeleteUser :one
DELETE
FROM users u
WHERE u.id = $1
  AND EXISTS (SELECT 1
              FROM users auth
              WHERE auth.id = $2
                AND auth.role IN ('manager', 'owner')
                AND auth.tenant_id = $3)
RETURNING id, uid, tenant_id, email, name, role, created_at, updated_at
`

type DeleteUserParams struct {
	ID       int32       `json:"id"`
	ID_2     int32       `json:"id_2"`
	TenantID pgtype.Int4 `json:"tenant_id"`
}

// Delete a user by ID (only allowed for 'manager' and 'owner' within their tenant)
func (q *Queries) DeleteUser(ctx context.Context, arg DeleteUserParams) (Users, error) {
	row := q.db.QueryRow(ctx, deleteUser, arg.ID, arg.ID_2, arg.TenantID)
	var i Users
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.TenantID,
		&i.Email,
		&i.Name,
		&i.Role,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getUserByID = `-- name: GetUserByID :one
SELECT id, uid, tenant_id, email, name, role, created_at, updated_at
FROM users u
WHERE (id = $1 AND u.role = 'superadmin')
   OR (id = $1 AND u.tenant_id = $2)
`

type GetUserByIDParams struct {
	ID       int32       `json:"id"`
	TenantID pgtype.Int4 `json:"tenant_id"`
}

// Read a user by ID (superadmin can see all, others can see within their tenant)
func (q *Queries) GetUserByID(ctx context.Context, arg GetUserByIDParams) (Users, error) {
	row := q.db.QueryRow(ctx, getUserByID, arg.ID, arg.TenantID)
	var i Users
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.TenantID,
		&i.Email,
		&i.Name,
		&i.Role,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getUsers = `-- name: GetUsers :many
SELECT id, uid, tenant_id, email, name, role, created_at, updated_at
FROM users u
WHERE u.role = 'superadmin'
   OR u.tenant_id = $1
`

// Read all users (superadmin can see all, others can see within their tenant)
func (q *Queries) GetUsers(ctx context.Context, tenantID pgtype.Int4) ([]Users, error) {
	rows, err := q.db.Query(ctx, getUsers, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Users{}
	for rows.Next() {
		var i Users
		if err := rows.Scan(
			&i.ID,
			&i.Uid,
			&i.TenantID,
			&i.Email,
			&i.Name,
			&i.Role,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateUser = `-- name: UpdateUser :one
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
RETURNING id, uid, tenant_id, email, name, role, created_at, updated_at
`

type UpdateUserParams struct {
	ID       int32       `json:"id"`
	TenantID pgtype.Int4 `json:"tenant_id"`
	Email    string      `json:"email"`
	Name     pgtype.Text `json:"name"`
	Role     UserRole    `json:"role"`
	ID_2     int32       `json:"id_2"`
}

// Update a user by ID (only allowed for 'manager' and 'owner' within their tenant)
func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (Users, error) {
	row := q.db.QueryRow(ctx, updateUser,
		arg.ID,
		arg.TenantID,
		arg.Email,
		arg.Name,
		arg.Role,
		arg.ID_2,
	)
	var i Users
	err := row.Scan(
		&i.ID,
		&i.Uid,
		&i.TenantID,
		&i.Email,
		&i.Name,
		&i.Role,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
