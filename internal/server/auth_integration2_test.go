package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestAuth_APIKeyLifecycle(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	owner := signup(t, base, "owner@a.com", "supersecret")

	var ck struct {
		UID    string `json:"uid"`
		APIKey string `json:"api_key"`
	}
	if code := doJSON(t, http.MethodPost, base+"/api/apikeys", owner.APIKey,
		map[string]string{"name": "ci"}, &ck); code != http.StatusCreated {
		t.Fatalf("create key: status %d", code)
	}
	if code := doJSON(t, http.MethodGet, base+"/api/auth/me", ck.APIKey, nil, nil); code != http.StatusOK {
		t.Errorf("new key /me status = %d, want 200", code)
	}
	if code := doJSON(t, http.MethodDelete, base+"/api/apikeys/"+ck.UID, owner.APIKey, nil, nil); code != http.StatusNoContent {
		t.Errorf("revoke status = %d, want 204", code)
	}
	if code := doJSON(t, http.MethodGet, base+"/api/auth/me", ck.APIKey, nil, nil); code != http.StatusUnauthorized {
		t.Errorf("revoked key /me status = %d, want 401", code)
	}
	if code := doJSON(t, http.MethodDelete, base+"/api/apikeys/"+ck.UID, owner.APIKey, nil, nil); code != http.StatusNotFound {
		t.Errorf("re-revoke status = %d, want 404", code)
	}
}

func TestAuth_CrossTenantIsolation(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	a := signup(t, base, "owner@a.com", "supersecret")
	b := signup(t, base, "owner@b.com", "supersecret")
	tenantB := tenantIDByEmail(t, ctx, pc, "owner@b.com")
	dom := seedDomain(t, ctx, pc, tenantB, "b-owned.example.com")

	// Every read/mutate path that resolves through DomainsGetByID must 404 for A.
	paths := []struct {
		method, url string
	}{
		{http.MethodGet, "/api/domains/" + dom.Uid},
		{http.MethodGet, "/api/domains/" + dom.Uid + "/records"},
		{http.MethodGet, "/api/domains/" + dom.Uid + "/records/history"},
		{http.MethodGet, "/api/domains/" + dom.Uid + "/timeline"},
		{http.MethodGet, "/api/domains/" + dom.Uid + "/impact"},
		{http.MethodDelete, "/api/domains/" + dom.Uid},
	}
	for _, p := range paths {
		if code := doJSON(t, p.method, base+p.url, a.APIKey, nil, nil); code != http.StatusNotFound {
			t.Errorf("A -> %s %s status = %d, want 404", p.method, p.url, code)
		}
	}
	// PUT cross-tenant 404s at the lookup, before any scan enqueue.
	if code := doJSON(t, http.MethodPut, base+"/api/domains/"+dom.Uid, a.APIKey,
		map[string]string{"status": "inactive"}, nil); code != http.StatusNotFound {
		t.Errorf("A -> PUT status = %d, want 404", code)
	}
	// B still sees its own domain (A's failed delete did not remove it).
	if code := doJSON(t, http.MethodGet, base+"/api/domains/"+dom.Uid, b.APIKey, nil, nil); code != http.StatusOK {
		t.Errorf("B -> GET own domain status = %d, want 200", code)
	}
}

func TestAuth_InviteFlow(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	owner := signup(t, base, "owner@a.com", "supersecret")
	tenantA := tenantIDByEmail(t, ctx, pc, "owner@a.com")
	ownerUser, err := pc.Queries.UserGetByEmail(ctx, "owner@a.com")
	if err != nil {
		t.Fatalf("owner lookup: %v", err)
	}

	// Invite + accept creates the user with the invited role in the same tenant.
	var inv struct {
		Token string `json:"token"`
	}
	if code := doJSON(t, http.MethodPost, base+"/api/invitations", owner.APIKey,
		map[string]string{"email": "viewer@a.com", "role": "viewer"}, &inv); code != http.StatusCreated {
		t.Fatalf("invite: status %d", code)
	}
	var acc tokenResp
	if code := doJSON(t, http.MethodPost, base+"/api/invitations/accept", "",
		map[string]string{"token": inv.Token, "password": "supersecret"}, &acc); code != http.StatusCreated {
		t.Fatalf("accept: status %d", code)
	}
	if acc.Role != "viewer" {
		t.Errorf("accepted role = %q, want viewer", acc.Role)
	}
	if got := tenantIDByEmail(t, ctx, pc, "viewer@a.com"); got != tenantA {
		t.Errorf("invited user tenant = %d, want %d", got, tenantA)
	}
	// Viewer cannot create an API key (owner/manager only).
	if code := doJSON(t, http.MethodPost, base+"/api/apikeys", acc.APIKey,
		map[string]string{"name": "x"}, nil); code != http.StatusForbidden {
		t.Errorf("viewer create key status = %d, want 403", code)
	}
	// Invalid token rejected.
	if code := doJSON(t, http.MethodPost, base+"/api/invitations/accept", "",
		map[string]string{"token": "bogus", "password": "supersecret"}, nil); code != http.StatusBadRequest {
		t.Errorf("bad token status = %d, want 400", code)
	}
	// Inviting an already-registered email → 409.
	if code := doJSON(t, http.MethodPost, base+"/api/invitations", owner.APIKey,
		map[string]string{"email": "viewer@a.com", "role": "viewer"}, nil); code != http.StatusConflict {
		t.Errorf("invite existing email status = %d, want 409", code)
	}

	// Revoked invite cannot be accepted.
	var inv2 struct {
		Token string `json:"token"`
	}
	if code := doJSON(t, http.MethodPost, base+"/api/invitations", owner.APIKey,
		map[string]string{"email": "pending@a.com", "role": "manager"}, &inv2); code != http.StatusCreated {
		t.Fatalf("invite pending: status %d", code)
	}
	var list struct {
		Invitations []struct {
			UID   string `json:"uid"`
			Email string `json:"email"`
		} `json:"invitations"`
	}
	if code := doJSON(t, http.MethodGet, base+"/api/invitations", owner.APIKey, nil, &list); code != http.StatusOK {
		t.Fatalf("list invitations: status %d", code)
	}
	var pendingUID string
	for _, iv := range list.Invitations {
		if iv.Email == "pending@a.com" {
			pendingUID = iv.UID
		}
	}
	if pendingUID == "" {
		t.Fatal("pending invite not listed")
	}
	if code := doJSON(t, http.MethodDelete, base+"/api/invitations/"+pendingUID, owner.APIKey, nil, nil); code != http.StatusNoContent {
		t.Errorf("revoke invite status = %d, want 204", code)
	}
	if code := doJSON(t, http.MethodPost, base+"/api/invitations/accept", "",
		map[string]string{"token": inv2.Token, "password": "supersecret"}, nil); code != http.StatusBadRequest {
		t.Errorf("accept revoked status = %d, want 400", code)
	}

	// An expired open invite is replaced by a fresh invite to the same email.
	if _, err := pc.Queries.InvitationCreate(ctx, store.InvitationCreateParams{
		TenantID:  tenantA,
		Email:     "stale@a.com",
		Role:      store.UserRoleViewer,
		TokenHash: auth.HashToken("old-token"),
		InvitedBy: pgtype.Int4{Int32: ownerUser.ID, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Hour), Valid: true},
	}); err != nil {
		t.Fatalf("seed expired invite: %v", err)
	}
	if code := doJSON(t, http.MethodPost, base+"/api/invitations", owner.APIKey,
		map[string]string{"email": "stale@a.com", "role": "viewer"}, nil); code != http.StatusCreated {
		t.Errorf("re-invite over expired status = %d, want 201", code)
	}
}

func TestAuth_InactiveUserRejected(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	owner := signup(t, base, "owner@a.com", "supersecret")
	if _, err := pc.Pool.Exec(ctx, `UPDATE users SET status = 'inactive' WHERE email = $1`, "owner@a.com"); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	// Login denied.
	if code := doJSON(t, http.MethodPost, base+"/api/auth/login", "",
		map[string]string{"email": "owner@a.com", "password": "supersecret"}, nil); code != http.StatusUnauthorized {
		t.Errorf("inactive login status = %d, want 401", code)
	}
	// Existing key denied.
	if code := doJSON(t, http.MethodGet, base+"/api/auth/me", owner.APIKey, nil, nil); code != http.StatusUnauthorized {
		t.Errorf("inactive key /me status = %d, want 401", code)
	}
}

func TestAuth_UserManagementScoping(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)
	_, base := newAuthAPI(t, pc)

	a := signup(t, base, "owner@a.com", "supersecret")
	signup(t, base, "owner@b.com", "supersecret")
	bUser, err := pc.Queries.UserGetByEmail(ctx, "owner@b.com")
	if err != nil {
		t.Fatalf("b user lookup: %v", err)
	}

	// A only sees its own tenant's users.
	var listA struct {
		Users []struct {
			Email string `json:"email"`
		} `json:"users"`
	}
	if code := doJSON(t, http.MethodGet, base+"/api/users", a.APIKey, nil, &listA); code != http.StatusOK {
		t.Fatalf("list users: status %d", code)
	}
	if len(listA.Users) != 1 || listA.Users[0].Email != "owner@a.com" {
		t.Errorf("A sees users = %+v, want only owner@a.com", listA.Users)
	}
	// A cannot update or delete B's user.
	if code := doJSON(t, http.MethodPut, base+"/api/users/"+bUser.Uid, a.APIKey,
		map[string]string{"email": "owner@b.com", "role": "viewer"}, nil); code != http.StatusNotFound {
		t.Errorf("A update B user status = %d, want 404", code)
	}
	if code := doJSON(t, http.MethodDelete, base+"/api/users/"+bUser.Uid, a.APIKey, nil, nil); code != http.StatusNotFound {
		t.Errorf("A delete B user status = %d, want 404", code)
	}
}
