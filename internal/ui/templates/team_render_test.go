package templates_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/ui/templates"
)

func teamMembers() []templates.MemberRowView {
	return []templates.MemberRowView{
		{
			UID: "user_owner", Email: "jane@acme.io", Initials: "JA",
			Role: "owner", Status: "active", StatusClass: "ok", Joined: "2025-12-01",
		},
		{
			UID: "user_mgr", Email: "sam@acme.io", Name: "Sam", Initials: "SA",
			Role: "manager", Status: "active", StatusClass: "ok", Joined: "2026-01-14",
		},
		{
			UID: "user_view", Email: "lee@acme.io", Initials: "LE",
			Role: "viewer", Status: "active", StatusClass: "ok", Joined: "2026-02-02",
		},
	}
}

func teamInvites() []templates.InviteRowView {
	return []templates.InviteRowView{
		{
			UID:       "inv_live",
			Email:     "new@acme.io",
			Role:      "viewer",
			InvitedBy: "jane@acme.io",
			Expires:   "in 6d",
		},
		{
			UID:       "inv_old",
			Email:     "old@acme.io",
			Role:      "manager",
			InvitedBy: "jane@acme.io",
			Expired:   true,
		},
	}
}

func teamProps(
	actorRole string,
	canManage bool,
	members []templates.MemberRowView,
	invites []templates.InviteRowView,
) templates.TeamPageProps {
	// Mark members manageable as the real handler would: actor outranks-or-equals.
	rank := map[string]int{"viewer": 1, "manager": 2, "owner": 3}
	for i := range members {
		members[i].Manageable = canManage && rank[actorRole] >= rank[members[i].Role]
	}
	return templates.TeamPageProps{
		Shell: templates.AppShellProps{
			UserEmail: "jane@acme.io",
			ActiveNav: "team",
			CSRFToken: "tok",
		},
		Stats: templates.TeamStats{
			Members:  len(members),
			Owners:   1,
			Managers: 1,
			Pending:  len(invites),
		},
		ActorRole: actorRole,
		Members:   members,
		Invites:   invites,
		CanManage: canManage,
	}
}

func renderTeam(t *testing.T, props templates.TeamPageProps) string {
	t.Helper()
	var buf bytes.Buffer
	if err := templates.TeamPage(props).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

func TestTeamPage_OwnerSeesAllControls(t *testing.T) {
	out := renderTeam(t, teamProps("owner", true, teamMembers(), teamInvites()))

	if !strings.Contains(out, "/app/team/invitations") {
		t.Error("expected invite form for an owner")
	}
	if !strings.Contains(out, "role-sel") || !strings.Contains(out, "/app/team/members/") {
		t.Error("expected inline role selects for an owner")
	}
	if !strings.Contains(out, "@delete(") || !strings.Contains(out, "/app/team/members/") {
		t.Error("expected remove controls for an owner")
	}
	// An owner can grant every role, so the owner option must be offered somewhere.
	if !strings.Contains(out, `value="owner"`) {
		t.Error("owner should be able to grant the owner role")
	}
	if !strings.Contains(out, "X-CSRF-Token") {
		t.Error("expected CSRF header on the team actions")
	}
}

func TestTeamPage_ManagerCannotGrantOwner(t *testing.T) {
	out := renderTeam(t, teamProps("manager", true, teamMembers(), teamInvites()))

	// A manager's grantable set is {viewer, manager}; the owner role must never be
	// offered as a selectable option (neither in the invite form nor any row select).
	if strings.Contains(out, `value="owner"`) {
		t.Error("a manager must not be offered the owner role as an option")
	}
	// The owner member outranks the manager, so that row must have no controls — it
	// renders the role as a static badge, not a select.
	if !strings.Contains(out, `class="badge role-owner"`) {
		t.Error("expected the owner member to render as a static role badge for a manager")
	}
	// Manageable members (viewer/manager) still get controls.
	if !strings.Contains(out, "role-sel") {
		t.Error("a manager should still manage lower-or-equal-rank members")
	}
}

func TestTeamPage_ViewerHidesControls(t *testing.T) {
	out := renderTeam(t, teamProps("viewer", false, teamMembers(), teamInvites()))

	if strings.Contains(out, "/app/team/invitations") {
		t.Error("a viewer must not see the invite form")
	}
	if strings.Contains(out, "role-sel") {
		t.Error("a viewer must not see role selects")
	}
	if strings.Contains(out, "@delete(") {
		t.Error("a viewer must not see remove/revoke controls")
	}
	// The viewer still sees the roster (read-only).
	if !strings.Contains(out, "lee@acme.io") {
		t.Error("a viewer should still see the member list")
	}
}

func TestTeamPage_ExpiredInviteRendersBadge(t *testing.T) {
	out := renderTeam(t, teamProps("owner", true, teamMembers(), teamInvites()))

	if !strings.Contains(out, "expired") {
		t.Error("expected an 'expired' marker for the expired invite")
	}
	if !strings.Contains(out, "expires in 6d") {
		t.Error("expected the live invite to show its relative expiry")
	}
	if !strings.Contains(out, "invited by jane@acme.io") {
		t.Error("expected the inviter email on pending invites")
	}
}

func TestInviteLinkReveal_ShowsURLOnceWithCopy(t *testing.T) {
	var buf bytes.Buffer
	if err := templates.InviteLinkReveal(templates.InviteLinkView{
		Email: "new@acme.io",
		URL:   "https://gecko.example/app/invite?token=abc123",
	}).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "https://gecko.example/app/invite?token=abc123") {
		t.Error("expected the invite URL in the reveal")
	}
	if !strings.Contains(out, "shown once") {
		t.Error("expected the one-time warning")
	}
	if !strings.Contains(out, "navigator.clipboard.writeText") {
		t.Error("expected a copy affordance")
	}
}

func TestMemberRow_MaliciousEmailCannotBreakOutOfJS(t *testing.T) {
	// An email crafted to terminate the confirm() string literal and inject a
	// statement. JSON-encoding it into a double-quoted JS string neutralises the
	// single quotes that would otherwise close the confirm() literal.
	evil := "x');alert(document.cookie);('"
	var buf bytes.Buffer
	if err := templates.MemberRow(
		templates.MemberRowView{UID: "user_x", Email: evil, Role: "viewer", Manageable: true},
		"owner",
		"tok",
		true,
	).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()

	// The injected payload must be confined inside a JSON-encoded ("double-quoted")
	// JS string. templ escapes the wrapping double-quotes to &#34;, so the encoded
	// email appears between &#34; markers rather than bare inside confirm()'s quotes.
	if !strings.Contains(out, "&#34;x&#39;);alert(document.cookie);(&#39;&#34;") {
		t.Errorf("malicious email was not JSON-encoded into a JS string literal; got:\n%s", out)
	}
}

func TestTeamPage_EmptyStates(t *testing.T) {
	out := renderTeam(t, teamProps("owner", true, nil, nil))

	if !strings.Contains(out, "No members yet") {
		t.Error("expected the members empty state")
	}
	if !strings.Contains(out, "No pending invitations") {
		t.Error("expected the invitations empty state")
	}
}
