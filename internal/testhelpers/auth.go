package testhelpers

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/auth"
)

// PrincipalForEmail builds a live Principal for email from the user's default
// membership (role and tenant live on memberships now, not the user row). It
// fails the test if the user has no account or no membership.
func PrincipalForEmail(
	t *testing.T,
	ctx context.Context,
	pc *PostgresContainer,
	email string,
) *auth.Principal {
	t.Helper()
	u, err := pc.Queries.UserGetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("principal for %s: lookup user: %v", email, err)
	}
	ms, err := pc.Queries.MembershipsListForUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("principal for %s: list memberships: %v", email, err)
	}
	def, ok := auth.DefaultMembership(ms)
	if !ok {
		t.Fatalf("principal for %s: no membership", email)
	}
	return &auth.Principal{
		UserID:   u.ID,
		TenantID: def.TenantID,
		Email:    u.Email,
		Role:     string(def.Role),
	}
}

// TenantIDForEmail returns the tenant id of the user's default membership.
func TenantIDForEmail(
	t *testing.T,
	ctx context.Context,
	pc *PostgresContainer,
	email string,
) int32 {
	t.Helper()
	return PrincipalForEmail(t, ctx, pc, email).TenantID
}
