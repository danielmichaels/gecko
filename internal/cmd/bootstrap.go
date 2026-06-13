package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type bootstrapParams struct {
	Email      string
	Password   string
	TenantName string
}

// bootstrapOwner idempotently ensures an owner user and a tenant exist. It adopts
// the lowest-id tenant when one is present (so an existing single-tenant install
// becomes reachable) and creates TenantName otherwise. A missing owner is
// provisioned with the owner role.
//
// resetPassword decides what happens when the owner already exists: true
// overwrites the credential — the explicit intent behind `auth bootstrap`; false
// leaves it untouched, so the auto-bootstrap-on-serve path cannot clobber a
// changed password every time the container restarts. It returns the tenant id
// and whether the owner was newly created.
func bootstrapOwner(
	ctx context.Context,
	pool *pgxpool.Pool,
	q *store.Queries,
	bcryptCost int,
	p bootstrapParams,
	resetPassword bool,
) (int32, bool, error) {
	email := strings.ToLower(strings.TrimSpace(p.Email))

	var tenantID int32
	err := pool.QueryRow(ctx, `SELECT id FROM tenants ORDER BY id LIMIT 1`).Scan(&tenantID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		t, cerr := q.TenantCreate(ctx, p.TenantName)
		if cerr != nil {
			return 0, false, fmt.Errorf("create tenant: %w", cerr)
		}
		tenantID = t.ID
	case err != nil:
		return 0, false, fmt.Errorf("look up tenant: %w", err)
	}

	var userID int32
	created := false
	existing, gerr := q.UserGetByEmail(ctx, email)
	switch {
	case gerr == nil:
		if !resetPassword {
			return tenantID, false, nil
		}
		userID = existing.ID
	case errors.Is(gerr, pgx.ErrNoRows):
		u, perr := q.UserProvision(ctx, store.UserProvisionParams{
			TenantID: pgtype.Int4{Int32: tenantID, Valid: true},
			Email:    email,
			Role:     store.UserRoleOwner,
		})
		if perr != nil {
			return 0, false, fmt.Errorf("provision owner: %w", perr)
		}
		userID = u.ID
		created = true
	default:
		return 0, false, fmt.Errorf("look up user: %w", gerr)
	}

	hash, herr := auth.HashPassword(p.Password, bcryptCost)
	if herr != nil {
		return 0, false, fmt.Errorf("hash password: %w", herr)
	}
	if err := q.UserCredentialUpsert(ctx, store.UserCredentialUpsertParams{
		UserID:       userID,
		PasswordHash: hash,
	}); err != nil {
		return 0, false, fmt.Errorf("set credentials: %w", err)
	}
	return tenantID, created, nil
}
