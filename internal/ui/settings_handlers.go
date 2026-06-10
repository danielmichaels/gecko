package ui

import (
	"errors"
	"net/http"
	"strings"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/ui/templates"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	datastar "github.com/starfederation/datastar-go/datastar"
)

// keyPermissionDeniedDesc is the toast body shown when a viewer attempts an
// API-key mutation. The controls are hidden for viewers, so this is the backstop
// for a forged or stale request rather than the primary feedback path.
const keyPermissionDeniedDesc = "You don't have permission to manage API keys"

// handleSettingsGet renders the settings page: the caller's API keys and the
// password-change form.
func (h *Handlers) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := h.svc.APIKeysService().ListMine(r.Context(), p)
	if err != nil {
		h.log.Error("settings: list keys", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	shell, err := h.shell(r.Context(), "settings")
	if err != nil {
		h.log.Error("settings: build shell", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	renderPage(w, r, templates.SettingsPage(templates.SettingsPageProps{
		Shell:     shell,
		APIKeys:   apiKeyRows(rows),
		CanManage: service.OwnerOrManager(p),
	}))
}

// handleAPIKeyCreate mints a new API key via a datastar SSE POST and reveals the
// plaintext secret exactly once.
func (h *Handlers) handleAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var form struct {
		NewKeyName string `json:"newKeyName"`
	}
	if err := datastar.ReadSignals(r, &form); err != nil {
		h.log.Error("apikey create: read signals", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	sse := datastar.NewSSE(w, r)

	name := strings.TrimSpace(form.NewKeyName)
	if name == "" {
		pushToast(
			sse,
			newToast("warn", "NOTICE", "Name required", "Give the key a name before creating it"),
		)
		return
	}

	result, err := h.svc.APIKeysService().Create(r.Context(), p, name)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			pushToast(sse, newToast("warn", "NOTICE", "Permission denied", keyPermissionDeniedDesc))
			return
		}
		h.log.Error("apikey create", "error", err)
		pushToast(sse, newToast("crit", "ERROR", "Failed to create key", name))
		return
	}

	_ = sse.PatchElementTempl(
		templates.APIKeySecret(templates.APIKeySecretView{Name: name, Raw: result.Raw}),
		datastar.WithSelectorID("apikey-secret"),
		datastar.WithModeInner(),
	)
	h.patchKeyRows(r, sse, p)
	pushToast(sse, newToast("ok", "API KEY", "Key created", name+" is ready to use"))
	_ = sse.MarshalAndPatchSignals(map[string]any{"newKeyName": ""})
}

// handleAPIKeyRevoke revokes an API key via a datastar SSE DELETE and re-renders
// the key list so the revoked key reads as inert.
func (h *Handlers) handleAPIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")
	sse := datastar.NewSSE(w, r)

	err := h.svc.APIKeysService().Revoke(r.Context(), p, uid)
	if errors.Is(err, service.ErrForbidden) {
		pushToast(sse, newToast("warn", "NOTICE", "Permission denied", keyPermissionDeniedDesc))
		return
	}
	if err != nil && !errors.Is(err, service.ErrNotFound) {
		h.log.Error("apikey revoke", "error", err, "uid", uid)
		pushToast(sse, newToast("crit", "ERROR", "Failed to revoke key", uid))
		return
	}

	h.patchKeyRows(r, sse, p)
	pushToast(sse, newToast("ok", "API KEY", "Key revoked", "the key can no longer authenticate"))
}

// handlePasswordChange verifies the caller's current password and sets a new one.
func (h *Handlers) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var form struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	if err := datastar.ReadSignals(r, &form); err != nil {
		h.log.Error("password change: read signals", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	sse := datastar.NewSSE(w, r)

	if form.NewPassword != form.ConfirmPassword {
		pushToast(
			sse,
			newToast("warn", "NOTICE", "Passwords do not match", "Re-enter the new password"),
		)
		return
	}

	err := h.svc.AuthService().
		ChangePassword(r.Context(), p, form.CurrentPassword, form.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrInvalidInput) {
			pushToast(sse, newToast("warn", "NOTICE", "Could not update password", err.Error()))
			return
		}
		h.log.Error("password change", "error", err)
		pushToast(sse, newToast("crit", "ERROR", "Failed to update password", "please try again"))
		return
	}

	pushToast(sse, newToast("ok", "ACCOUNT", "Password updated", "your new password is active"))
	_ = sse.MarshalAndPatchSignals(map[string]any{
		"currentPassword": "",
		"newPassword":     "",
		"confirmPassword": "",
	})
}

// patchKeyRows re-renders #apikey-rows from the caller's current key set. Shared
// by the create and revoke flows so both reflect the same server-truth ordering.
func (h *Handlers) patchKeyRows(
	r *http.Request,
	sse *datastar.ServerSentEventGenerator,
	p *auth.Principal,
) {
	rows, err := h.svc.APIKeysService().ListMine(r.Context(), p)
	if err != nil {
		h.log.Error("apikey list: re-render", "error", err)
		return
	}
	_ = sse.PatchElementTempl(
		templates.APIKeyRows(
			apiKeyRows(rows),
			CSRFTokenFrom(r.Context()),
			service.OwnerOrManager(p),
		),
		datastar.WithSelectorID("apikey-rows"),
		datastar.WithModeInner(),
	)
}

// apiKeyRows maps store rows to the presentation model.
func apiKeyRows(rows []store.ApiKeysListByUserRow) []templates.APIKeyRowView {
	views := make([]templates.APIKeyRowView, len(rows))
	for i, r := range rows {
		views[i] = templates.APIKeyRowView{
			UID:      r.Uid,
			Name:     r.Name,
			Prefix:   r.Prefix,
			Created:  relativeTime(r.CreatedAt),
			LastUsed: relativeTime(r.LastUsedAt),
			Expires:  expiryLabel(r.ExpiresAt),
			Revoked:  r.RevokedAt.Valid,
		}
	}
	return views
}

// expiryLabel renders a key's expiry as an absolute date, or "never" when the
// key has no expiry set.
func expiryLabel(t pgtype.Timestamptz) string {
	if !t.Valid {
		return "never"
	}
	return t.Time.Format("2006-01-02")
}
