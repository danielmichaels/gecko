package ui

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/ui/templates"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	datastar "github.com/starfederation/datastar-go/datastar"
)

// teamPermissionDeniedDesc is the toast body shown when a viewer attempts a team
// mutation. The controls are hidden for viewers, so this is the backstop for a
// forged or stale request rather than the primary feedback path.
const teamPermissionDeniedDesc = "You don't have permission to manage the team"

// teamRoleRank mirrors service/authz.go's privilege ordering so the handler can
// decide row manageability. The service guard remains authoritative.
var teamRoleRank = map[string]int{"viewer": 1, "manager": 2, "owner": 3, "superadmin": 4}

// handleTeamGet renders the team page: members with per-row role controls and the
// pending-invitation list with the inline invite form.
func (h *Handlers) handleTeamGet(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	members, invites, err := h.teamData(r.Context(), p)
	if err != nil {
		h.log.Error("team: load", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	shell, err := h.shell(r.Context(), "team")
	if err != nil {
		h.log.Error("team: build shell", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	renderPage(w, r, templates.TeamPage(templates.TeamPageProps{
		Shell:     shell,
		Stats:     teamStats(members, invites),
		ActorRole: p.Role,
		Members:   members,
		Invites:   invites,
		CanManage: service.OwnerOrManager(p),
	}))
}

// handleTeamInviteCreate issues an invitation and reveals its one-time accept link.
// With no mailer wired, the reveal is the sole delivery channel.
func (h *Handlers) handleTeamInviteCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var form struct {
		InviteEmail string `json:"inviteEmail"`
		InviteRole  string `json:"inviteRole"`
	}
	if err := datastar.ReadSignals(r, &form); err != nil {
		h.log.Error("team invite: read signals", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	sse := datastar.NewSSE(w, r)

	email := strings.TrimSpace(form.InviteEmail)
	if email == "" {
		pushToast(sse, newToast("warn", "NOTICE", "Email required", "Enter an email to invite"))
		return
	}

	result, err := h.svc.InvitationsService().
		Create(r.Context(), p, service.InvitationsCreateParams{
			Email: email,
			Role:  form.InviteRole,
		})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			pushToast(
				sse,
				newToast("warn", "NOTICE", "Permission denied", teamPermissionDeniedDesc),
			)
		case errors.Is(err, service.ErrConflict):
			pushToast(sse, newToast("warn", "NOTICE", "Could not invite", err.Error()))
		default:
			h.log.Error("team invite create", "error", err)
			pushToast(sse, newToast("crit", "ERROR", "Failed to invite", email))
		}
		return
	}

	inviteURL := requestBaseURL(r) + "/app/invite?token=" + result.Token
	_ = sse.PatchElementTempl(
		templates.InviteLinkReveal(templates.InviteLinkView{Email: result.Email, URL: inviteURL}),
		datastar.WithSelectorID("team-invite-secret"),
		datastar.WithModeInner(),
	)
	h.patchTeam(r, sse, p)
	pushToast(sse, newToast("ok", "TEAM", "Invitation created", result.Email))
	_ = sse.MarshalAndPatchSignals(map[string]any{"inviteEmail": "", "inviteRole": "viewer"})
}

// handleTeamInviteRevoke revokes a pending invitation so its link can no longer be
// accepted.
func (h *Handlers) handleTeamInviteRevoke(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")
	sse := datastar.NewSSE(w, r)

	err := h.svc.InvitationsService().Revoke(r.Context(), p, uid)
	switch {
	case err == nil, errors.Is(err, service.ErrNotFound):
		h.patchTeam(r, sse, p)
		pushToast(
			sse,
			newToast("ok", "TEAM", "Invitation revoked", "the link can no longer be used"),
		)
	case errors.Is(err, service.ErrForbidden):
		pushToast(sse, newToast("warn", "NOTICE", "Permission denied", teamPermissionDeniedDesc))
	default:
		h.log.Error("team invite revoke", "error", err, "uid", uid)
		pushToast(sse, newToast("crit", "ERROR", "Failed to revoke invitation", uid))
	}
}

// handleTeamMemberRole changes a member's role. The new role arrives as the ?role
// query param; the member's current email/name are carried through because the
// update rewrites identity (email/name) alongside the membership role.
func (h *Handlers) handleTeamMemberRole(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")
	role := strings.TrimSpace(r.URL.Query().Get("role"))
	sse := datastar.NewSSE(w, r)

	current, err := h.findMember(r.Context(), p, uid)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			pushToast(sse, newToast("warn", "NOTICE", "Member not found", "nothing to update"))
			return
		}
		h.log.Error("team role: lookup", "error", err, "uid", uid)
		pushToast(sse, newToast("crit", "ERROR", "Failed to update role", uid))
		return
	}

	_, err = h.svc.UsersService().Update(r.Context(), p, uid, service.UsersUpdateParams{
		Email: current.Email,
		Name:  current.Name,
		Role:  role,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			pushToast(
				sse,
				newToast("warn", "NOTICE", "Permission denied", teamPermissionDeniedDesc),
			)
		case errors.Is(err, service.ErrConflict):
			pushToast(sse, newToast("warn", "NOTICE", "Could not change role", err.Error()))
		case errors.Is(err, service.ErrNotFound):
			pushToast(sse, newToast("warn", "NOTICE", "Member not found", "nothing to update"))
		default:
			h.log.Error("team role update", "error", err, "uid", uid)
			pushToast(sse, newToast("crit", "ERROR", "Failed to update role", current.Email))
		}
		// Re-render so the select snaps back to the server's truth.
		h.patchTeam(r, sse, p)
		return
	}

	h.patchTeam(r, sse, p)
	pushToast(sse, newToast("ok", "TEAM", "Role updated", current.Email+" · "+role))
}

// handleTeamMemberRemove removes a member from the tenant. The last-owner guard can
// legitimately reject this with a conflict, surfaced as a toast.
func (h *Handlers) handleTeamMemberRemove(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")
	sse := datastar.NewSSE(w, r)

	err := h.svc.UsersService().Delete(r.Context(), p, uid)
	switch {
	case err == nil, errors.Is(err, service.ErrNotFound):
		h.patchTeam(r, sse, p)
		pushToast(
			sse,
			newToast("ok", "TEAM", "Member removed", "they can no longer access this tenant"),
		)
	case errors.Is(err, service.ErrForbidden):
		pushToast(sse, newToast("warn", "NOTICE", "Permission denied", teamPermissionDeniedDesc))
	case errors.Is(err, service.ErrConflict):
		pushToast(sse, newToast("warn", "NOTICE", "Cannot remove member", err.Error()))
	default:
		h.log.Error("team member remove", "error", err, "uid", uid)
		pushToast(sse, newToast("crit", "ERROR", "Failed to remove member", uid))
	}
}

// patchTeam re-renders the members and invites fragments plus the stat strip from
// current server state. Shared by every mutation so all three reflect one truth.
func (h *Handlers) patchTeam(
	r *http.Request,
	sse *datastar.ServerSentEventGenerator,
	p *auth.Principal,
) {
	members, invites, err := h.teamData(r.Context(), p)
	if err != nil {
		h.log.Error("team: re-render", "error", err)
		return
	}
	props := templates.TeamPageProps{
		Shell:     templates.AppShellProps{CSRFToken: CSRFTokenFrom(r.Context())},
		ActorRole: p.Role,
		Members:   members,
		Invites:   invites,
		CanManage: service.OwnerOrManager(p),
	}
	_ = sse.PatchElementTempl(
		templates.TeamMembersFragment(props),
		datastar.WithSelectorID("team-members"),
		datastar.WithModeInner(),
	)
	_ = sse.PatchElementTempl(
		templates.TeamInvitesFragment(props),
		datastar.WithSelectorID("team-invites"),
		datastar.WithModeInner(),
	)
	_ = sse.PatchElementTempl(
		templates.TeamStatsStrip(teamStats(members, invites)),
		datastar.WithSelectorID("team-stats"),
		datastar.WithModeInner(),
	)
}

// teamData fetches the tenant's members and pending invitations and maps them to
// presentation models. Accepted invites are dropped; expired ones are kept (dimmed)
// so they remain revocable.
func (h *Handlers) teamData(
	ctx context.Context,
	p *auth.Principal,
) ([]templates.MemberRowView, []templates.InviteRowView, error) {
	users, err := h.svc.UsersService().List(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	invs, err := h.svc.InvitationsService().List(ctx, p)
	if err != nil {
		return nil, nil, err
	}

	emailByID := make(map[int32]string, len(users))
	for _, u := range users {
		emailByID[u.UserID] = u.Email
	}

	members := make([]templates.MemberRowView, len(users))
	for i, u := range users {
		members[i] = templates.MemberRowView{
			UID:         u.UID,
			Email:       u.Email,
			Name:        u.Name,
			Initials:    initials(u.Email),
			Role:        u.Role,
			Status:      u.Status,
			StatusClass: memberStatusClass(u.Status),
			Joined:      joinedLabel(u.JoinedAt),
			Manageable:  canManageMemberRole(p.Role, u.Role),
		}
	}

	now := time.Now()
	var invites []templates.InviteRowView
	for _, inv := range invs {
		if inv.AcceptedAt.Valid {
			continue
		}
		invitedBy := ""
		if inv.InvitedBy.Valid {
			invitedBy = emailByID[inv.InvitedBy.Int32]
		}
		invites = append(invites, templates.InviteRowView{
			UID:       inv.Uid,
			Email:     inv.Email,
			Role:      string(inv.Role),
			InvitedBy: invitedBy,
			Expires:   expiresLabel(inv.ExpiresAt, now),
			Expired:   inv.ExpiresAt.Valid && inv.ExpiresAt.Time.Before(now),
		})
	}
	return members, invites, nil
}

// findMember resolves a single member by uid within the caller's tenant. There is
// no single-user service getter, so it scans the tenant list.
func (h *Handlers) findMember(
	ctx context.Context,
	p *auth.Principal,
	uid string,
) (service.Member, error) {
	users, err := h.svc.UsersService().List(ctx, p)
	if err != nil {
		return service.Member{}, err
	}
	for _, u := range users {
		if u.UID == uid {
			return u, nil
		}
	}
	return service.Member{}, service.ErrNotFound
}

// canManageMemberRole reports whether the actor outranks-or-equals the target role.
func canManageMemberRole(actorRole, targetRole string) bool {
	return teamRoleRank[actorRole] >= teamRoleRank[targetRole]
}

// teamStats derives the stat-strip counts from the mapped member/invite views.
func teamStats(
	members []templates.MemberRowView,
	invites []templates.InviteRowView,
) templates.TeamStats {
	s := templates.TeamStats{Members: len(members), Pending: len(invites)}
	for _, m := range members {
		switch m.Role {
		case "owner":
			s.Owners++
		case "manager":
			s.Managers++
		}
	}
	return s
}

// memberStatusClass maps a user status to its badge accent class.
func memberStatusClass(status string) string {
	switch status {
	case string(store.UserStatusActive):
		return "ok"
	case string(store.UserStatusPending):
		return "warn"
	default:
		return ""
	}
}

// joinedLabel renders a member's join date, or "—" when unset.
func joinedLabel(t pgtype.Timestamptz) string {
	if !t.Valid {
		return "—"
	}
	return t.Time.Format("2006-01-02")
}

// expiresLabel renders an invitation's time-to-expiry as a forward-relative label
// ("in 6d"), or "expired" once past.
func expiresLabel(t pgtype.Timestamptz, now time.Time) string {
	if !t.Valid {
		return "—"
	}
	d := t.Time.Sub(now)
	if d <= 0 {
		return "expired"
	}
	switch {
	case d < time.Hour:
		return "in " + strconv.Itoa(int(math.Round(d.Minutes()))) + "m"
	case d < 24*time.Hour:
		return "in " + strconv.Itoa(int(math.Round(d.Hours()))) + "h"
	default:
		return "in " + strconv.Itoa(int(math.Round(d.Hours()/24))) + "d"
	}
}

// requestBaseURL derives the public scheme+host for building absolute links (the
// invite accept URL). There is no configured base URL, so it is taken from the
// request, honouring a reverse proxy's X-Forwarded-Proto.
func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host
}
