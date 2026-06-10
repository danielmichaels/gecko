package ui_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/testhelpers"
)

// inviteBody encodes datastar signals JSON for a POST /app/team/invitations request.
func inviteBody(email, role string) []byte {
	b, _ := json.Marshal(map[string]string{"inviteEmail": email, "inviteRole": role})
	return b
}

func TestHandlerTeam_Get_OwnerSeesRoster(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, csrf := h.loginCookie(t, "owner@team.test", "secret123")

	rr := h.do(t, http.MethodGet, "/app/team", nil, cookie, csrf)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /app/team: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "owner@team.test") {
		t.Error("expected the owner to appear in the roster")
	}
	if !strings.Contains(body, "/app/team/invitations") {
		t.Error("expected the invite form for an owner")
	}
}

func TestHandlerTeam_InviteCreate_RevealsOneTimeLink(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, csrf := h.loginCookie(t, "owner@invite.test", "secret123")

	rr := h.do(
		t,
		http.MethodPost,
		"/app/team/invitations",
		inviteBody("newbie@invite.test", "viewer"),
		cookie,
		csrf,
	)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST invite: want 200 (SSE), got %d", rr.Code)
	}
	body := rr.Body.String()
	// The one-time accept link is the only delivery channel — it must be revealed
	// in the response with the token embedded.
	if !strings.Contains(body, "/app/invite?token=") {
		t.Errorf("expected the invite accept link in the reveal, got:\n%s", body)
	}
	if !strings.Contains(body, "shown once") {
		t.Error("expected the one-time reveal warning")
	}
}

func TestHandlerTeam_RemoveLastOwner_SurfacesConflict(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("create container: %v", err)
	}
	defer pc.Close(ctx)

	h := newUIHarness(t, pc)
	cookie, csrf := h.loginCookie(t, "soleowner@team.test", "secret123")

	owner, err := pc.Queries.UserGetByEmail(ctx, "soleowner@team.test")
	if err != nil {
		t.Fatalf("lookup owner: %v", err)
	}

	rr := h.doDelete(t, "/app/team/members/"+owner.Uid, nil, cookie, csrf)
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE last owner: want 200 (SSE), got %d", rr.Code)
	}
	// The last-owner guard's message must reach the user, not be swallowed.
	if !strings.Contains(rr.Body.String(), "cannot remove the last owner") {
		t.Errorf("expected the last-owner conflict surfaced as a toast, got:\n%s", rr.Body.String())
	}
	// The owner must still exist.
	if _, err := pc.Queries.UserGetByEmail(ctx, "soleowner@team.test"); err != nil {
		t.Errorf("sole owner should not have been removed: %v", err)
	}
}
