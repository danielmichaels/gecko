package cmd

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

// TestBootstrapOwner_IdempotentNoClobber pins the shared bootstrap core: the
// first run creates the tenant + owner; a second run with resetPassword=false
// (the auto-bootstrap-on-serve path) is a no-op that must NOT overwrite the
// existing password; resetPassword=true (the explicit CLI path) does reset it.
func TestBootstrapOwner_IdempotentNoClobber(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	const cost = 4

	tenantID, created, err := bootstrapOwner(
		ctx, pc.Pool, pc.Queries, cost,
		bootstrapParams{Email: "Owner@Example.com", Password: "first-pass", TenantName: "acme"},
		false,
	)
	if err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	if !created {
		t.Fatalf("first bootstrap: created=false, want true")
	}
	if tenantID == 0 {
		t.Fatalf("first bootstrap: tenantID=0")
	}

	owner, err := pc.Queries.UserGetByEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatalf("lookup owner: %v", err)
	}
	// Role lives on the membership now, not the user row.
	ownerRole, err := pc.Queries.MembershipGetRole(ctx, store.MembershipGetRoleParams{
		UserID:   owner.ID,
		TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("owner membership: %v", err)
	}
	if ownerRole != store.UserRoleOwner {
		t.Errorf("owner role = %q, want %q", ownerRole, store.UserRoleOwner)
	}
	cred1, err := pc.Queries.UserCredentialGetByUserID(ctx, owner.ID)
	if err != nil {
		t.Fatalf("get credential: %v", err)
	}

	// Auto-bootstrap path: existing owner, resetPassword=false -> no-op, password preserved.
	tid2, created2, err := bootstrapOwner(
		ctx, pc.Pool, pc.Queries, cost,
		bootstrapParams{Email: "owner@example.com", Password: "second-pass", TenantName: "acme"},
		false,
	)
	if err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}
	if created2 {
		t.Errorf("second bootstrap: created=true, want false (idempotent)")
	}
	if tid2 != tenantID {
		t.Errorf("second bootstrap: tenantID=%d, want %d (adopt existing tenant)", tid2, tenantID)
	}
	cred2, err := pc.Queries.UserCredentialGetByUserID(ctx, owner.ID)
	if err != nil {
		t.Fatalf("get credential after no-op: %v", err)
	}
	if cred2.PasswordHash != cred1.PasswordHash {
		t.Error("auto-bootstrap (resetPassword=false) overwrote the existing password")
	}

	// CLI path: resetPassword=true -> password is reset.
	if _, _, err := bootstrapOwner(
		ctx, pc.Pool, pc.Queries, cost,
		bootstrapParams{Email: "owner@example.com", Password: "third-pass", TenantName: "acme"},
		true,
	); err != nil {
		t.Fatalf("third bootstrap: %v", err)
	}
	cred3, err := pc.Queries.UserCredentialGetByUserID(ctx, owner.ID)
	if err != nil {
		t.Fatalf("get credential after reset: %v", err)
	}
	if cred3.PasswordHash == cred1.PasswordHash {
		t.Error("CLI bootstrap (resetPassword=true) did not reset the password")
	}
}
