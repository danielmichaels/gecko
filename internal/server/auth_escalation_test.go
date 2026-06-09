package server

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/danielmichaels/gecko/internal/testhelpers"
)

// inviteAccept invites email at role via inviterKey and immediately accepts the
// invitation, returning the new member's token (and API key). Used to mint members
// of a known role inside a tenant.
func inviteAccept(t *testing.T, base, inviterKey, email, role string) tokenResp {
	t.Helper()
	var inv struct {
		Token string `json:"token"`
	}
	if code := doJSON(t, http.MethodPost, base+"/api/invitations", inviterKey,
		map[string]string{"email": email, "role": role}, &inv); code != http.StatusCreated {
		t.Fatalf("invite %s as %s: status %d", email, role, code)
	}
	var acc tokenResp
	if code := doJSON(t, http.MethodPost, base+"/api/invitations/accept", "",
		map[string]string{"token": inv.Token, "password": "supersecret"}, &acc); code != http.StatusCreated {
		t.Fatalf("accept %s: status %d", email, code)
	}
	return acc
}

// TestAuth_RoleEscalation pins the privilege boundary: an actor may never grant a
// role above their own, via either the invitation or the user-update path. A manager
// must not be able to mint owners or promote anyone (including themselves) to owner;
// an owner still may.
func TestAuth_RoleEscalation(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	owner := signup(t, base, "owner@a.com", "supersecret")
	mgr := inviteAccept(t, base, owner.APIKey, "mgr@a.com", "manager")
	inviteAccept(t, base, owner.APIKey, "viewer@a.com", "viewer")

	mgrUser, err := pc.Queries.UserGetByEmail(ctx, "mgr@a.com")
	if err != nil {
		t.Fatalf("mgr lookup: %v", err)
	}
	viewerUser, err := pc.Queries.UserGetByEmail(ctx, "viewer@a.com")
	if err != nil {
		t.Fatalf("viewer lookup: %v", err)
	}

	// Invite path: a manager may invite at or below their own rank, but not owner.
	if code := doJSON(t, http.MethodPost, base+"/api/invitations", mgr.APIKey,
		map[string]string{"email": "peer@a.com", "role": "manager"}, nil); code != http.StatusCreated {
		t.Errorf("manager invite manager status = %d, want 201", code)
	}
	if code := doJSON(t, http.MethodPost, base+"/api/invitations", mgr.APIKey,
		map[string]string{"email": "escalate@a.com", "role": "owner"}, nil); code != http.StatusForbidden {
		t.Errorf("manager invite owner status = %d, want 403", code)
	}

	// Update path: a manager cannot promote another user to owner.
	if code := doJSON(t, http.MethodPut, base+"/api/users/"+viewerUser.Uid, mgr.APIKey,
		map[string]string{"email": "viewer@a.com", "role": "owner"}, nil); code != http.StatusForbidden {
		t.Errorf("manager promote viewer->owner status = %d, want 403", code)
	}

	// Self path: a manager cannot promote themselves to owner.
	if code := doJSON(t, http.MethodPut, base+"/api/users/"+mgrUser.Uid, mgr.APIKey,
		map[string]string{"email": "mgr@a.com", "role": "owner"}, nil); code != http.StatusForbidden {
		t.Errorf("manager self-promote->owner status = %d, want 403", code)
	}

	// Owner is unaffected: an owner may grant owner.
	if code := doJSON(t, http.MethodPut, base+"/api/users/"+viewerUser.Uid, owner.APIKey,
		map[string]string{"email": "viewer@a.com", "role": "owner"}, nil); code != http.StatusOK {
		t.Errorf("owner promote viewer->owner status = %d, want 200", code)
	}
}

// TestAuth_RoleProtection pins the other half of the boundary: an actor may not
// modify or delete a user who outranks them, regardless of the role being set. This
// closes the lateral takeover — a manager demoting/rewriting/deleting an owner — that
// the grant-rank check alone does not catch.
func TestAuth_RoleProtection(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	owner := signup(t, base, "owner@a.com", "supersecret")
	mgr := inviteAccept(t, base, owner.APIKey, "mgr@a.com", "manager")
	inviteAccept(t, base, owner.APIKey, "v1@a.com", "viewer")
	inviteAccept(t, base, owner.APIKey, "v2@a.com", "viewer")

	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "owner@a.com")
	if err != nil {
		t.Fatalf("owner lookup: %v", err)
	}
	v1, err := pc.Queries.UserGetByEmail(ctx, "v1@a.com")
	if err != nil {
		t.Fatalf("v1 lookup: %v", err)
	}
	v2, err := pc.Queries.UserGetByEmail(ctx, "v2@a.com")
	if err != nil {
		t.Fatalf("v2 lookup: %v", err)
	}

	// A manager cannot demote/rewrite an owner (account-takeover vector).
	if code := doJSON(t, http.MethodPut, base+"/api/users/"+ownerUser.Uid, mgr.APIKey,
		map[string]string{"email": "owner@a.com", "role": "viewer"}, nil); code != http.StatusForbidden {
		t.Errorf("manager edit owner status = %d, want 403", code)
	}
	// A manager cannot delete an owner.
	if code := doJSON(t, http.MethodDelete, base+"/api/users/"+ownerUser.Uid, mgr.APIKey,
		nil, nil); code != http.StatusForbidden {
		t.Errorf("manager delete owner status = %d, want 403", code)
	}
	// Control: a manager may still manage a viewer (at or below their rank).
	if code := doJSON(t, http.MethodPut, base+"/api/users/"+v1.Uid, mgr.APIKey,
		map[string]string{"email": "v1@a.com", "role": "viewer", "name": "Vee"}, nil); code != http.StatusOK {
		t.Errorf("manager edit viewer status = %d, want 200", code)
	}
	if code := doJSON(t, http.MethodDelete, base+"/api/users/"+v2.Uid, mgr.APIKey,
		nil, nil); code != http.StatusNoContent {
		t.Errorf("manager delete viewer status = %d, want 204", code)
	}
}

// TestAuth_LastOwnerProtected ensures a tenant cannot be orphaned: the sole owner
// can neither delete nor demote themselves out of the owner role.
func TestAuth_LastOwnerProtected(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	owner := signup(t, base, "owner@a.com", "supersecret")
	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "owner@a.com")
	if err != nil {
		t.Fatalf("owner lookup: %v", err)
	}

	// Sole owner cannot demote themselves.
	if code := doJSON(t, http.MethodPut, base+"/api/users/"+ownerUser.Uid, owner.APIKey,
		map[string]string{"email": "owner@a.com", "role": "manager"}, nil); code != http.StatusConflict {
		t.Errorf("sole owner self-demote status = %d, want 409", code)
	}
	// Sole owner cannot delete themselves.
	if code := doJSON(t, http.MethodDelete, base+"/api/users/"+ownerUser.Uid, owner.APIKey,
		nil, nil); code != http.StatusConflict {
		t.Errorf("sole owner self-delete status = %d, want 409", code)
	}
}

// TestAuth_LastOwnerConcurrentDelete fires two simultaneous deletes of the two
// distinct owners of a tenant. The transactional last-owner guard must serialise
// them so exactly one succeeds and the tenant always retains an owner — without it,
// both could read "2 owners" and both delete, orphaning the tenant.
func TestAuth_LastOwnerConcurrentDelete(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	owner := signup(t, base, "owner@a.com", "supersecret")
	inviteAccept(t, base, owner.APIKey, "owner2@a.com", "owner")
	o1, err := pc.Queries.UserGetByEmail(ctx, "owner@a.com")
	if err != nil {
		t.Fatalf("o1 lookup: %v", err)
	}
	o2, err := pc.Queries.UserGetByEmail(ctx, "owner2@a.com")
	if err != nil {
		t.Fatalf("o2 lookup: %v", err)
	}

	uids := []string{o1.Uid, o2.Uid}
	codes := make([]int, len(uids))
	var wg sync.WaitGroup
	for idx := range uids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, reqErr := http.NewRequest(http.MethodDelete, base+"/api/users/"+uids[i], nil)
			if reqErr != nil {
				codes[i] = -1
				return
			}
			req.Header.Set("X-API-Key", owner.APIKey)
			resp, doErr := http.DefaultClient.Do(req)
			if doErr != nil {
				codes[i] = -1
				return
			}
			_ = resp.Body.Close()
			codes[i] = resp.StatusCode
		}(idx)
	}
	wg.Wait()

	// The guard's invariant: at most one deletion succeeds and the tenant is never
	// orphaned. The losing request may be rejected as 409 (last owner) or 401 (its key
	// belonged to the owner the sibling just deleted) — both are safe; only "both
	// succeeded" is a bug.
	var succeeded int
	for _, c := range codes {
		if c == http.StatusNoContent {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Errorf("status codes = %v, want exactly one 204", codes)
	}
	remaining, err := pc.Queries.UsersCountOwnersInTenant(ctx, o1.TenantID)
	if err != nil {
		t.Fatalf("count owners: %v", err)
	}
	if remaining != 1 {
		t.Errorf("owners remaining = %d, want 1 (tenant must never be orphaned)", remaining)
	}
}
