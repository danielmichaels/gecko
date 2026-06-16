package ui

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/ui/templates"
	"github.com/go-chi/chi/v5"
	datastar "github.com/starfederation/datastar-go/datastar"
)

// handleFindingSilence creates a silence rule from a finding row (tenant-global or
// per-domain) then re-renders the findings list so the now-suppressed row drops
// out. Owner/manager only.
func (h *Handlers) handleFindingSilence(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sse := datastar.NewSSE(w, r)

	kind := r.URL.Query().Get("kind")
	issueType := r.URL.Query().Get("issue_type")
	var domainUID *string
	if r.URL.Query().Get("scope") == "domain" {
		if d := r.URL.Query().Get("domain_uid"); d != "" {
			domainUID = &d
		}
	}

	_, err := h.svc.SuppressionsService().
		CreateSilenceRule(r.Context(), p, kind, issueType, domainUID, "", nil)
	if err != nil {
		h.suppressionToast(sse, err, "Failed to silence check")
		return
	}

	scopeLabel := "all domains"
	if domainUID != nil {
		scopeLabel = "this domain"
	}
	pushToast(sse, newToast("ok", "SILENCED", "Check silenced", "Hidden for "+scopeLabel))
	h.renderFindingsList(r.Context(), sse, p, r)
}

// handleFindingAcknowledgeUI acknowledges a single finding by uid, then re-renders
// the findings list. Owner/manager only.
func (h *Handlers) handleFindingAcknowledgeUI(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sse := datastar.NewSSE(w, r)

	uid := chi.URLParam(r, "uid")
	_, err := h.svc.SuppressionsService().
		AcknowledgeFinding(r.Context(), p, uid, store.SuppressionStateAcknowledged, "", nil)
	if err != nil {
		h.suppressionToast(sse, err, "Failed to acknowledge finding")
		return
	}
	pushToast(sse, newToast("ok", "ACKNOWLEDGED", "Finding acknowledged", "Marked as handled"))
	h.renderFindingsList(r.Context(), sse, p, r)
}

// handleSuppressionDelete removes a silence rule or ack and re-renders the
// settings "Silenced checks" list. Owner/manager only.
func (h *Handlers) handleSuppressionDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sse := datastar.NewSSE(w, r)

	uid := chi.URLParam(r, "uid")
	if err := h.svc.SuppressionsService().DeleteSuppression(r.Context(), p, uid); err != nil {
		h.suppressionToast(sse, err, "Failed to remove suppression")
		return
	}
	pushToast(sse, newToast("ok", "REMOVED", "Suppression removed", "The finding will appear again"))
	h.patchSilencedChecks(r.Context(), sse, p)
}

// renderFindingsList re-runs the tenant findings list with the current filter
// signals and patches #findings-list. Shared by the silence/ack actions.
func (h *Handlers) renderFindingsList(
	ctx context.Context,
	sse *datastar.ServerSentEventGenerator,
	p *auth.Principal,
	r *http.Request,
) {
	var sig struct {
		Sev           string `json:"sev"`
		Kind          string `json:"kind"`
		Q             string `json:"q"`
		ShowCompliant bool   `json:"showCompliant"`
		ShowSilenced  bool   `json:"showSilenced"`
	}
	_ = datastar.ReadSignals(r, &sig)
	opts := service.FindingsListOptions{
		Severity:          sig.Sev,
		Kind:              sig.Kind,
		DomainQuery:       strings.TrimSpace(sig.Q),
		IncludeCompliant:  sig.ShowCompliant,
		IncludeSuppressed: sig.ShowSilenced,
	}
	res, err := h.svc.FindingsService().ListByTenant(ctx, p, opts)
	if err != nil {
		h.log.Error("findings: re-list after suppression", "error", err)
		return
	}
	view := toTenantFindingsView(res, service.OwnerOrManager(p), opts.IncludeSuppressed, CSRFTokenFrom(ctx))
	_ = sse.PatchElementTempl(
		templates.FindingsListFragment(view),
		datastar.WithSelectorID("findings-list"),
		datastar.WithModeInner(),
	)
}

// patchSilencedChecks re-renders the settings "Silenced checks" list region.
func (h *Handlers) patchSilencedChecks(
	ctx context.Context,
	sse *datastar.ServerSentEventGenerator,
	p *auth.Principal,
) {
	rows, err := h.silencedRows(ctx, p)
	if err != nil {
		h.log.Error("settings: list suppressions", "error", err)
		return
	}
	_ = sse.PatchElementTempl(
		templates.SilencedChecksList(rows, CSRFTokenFrom(ctx), service.OwnerOrManager(p)),
		datastar.WithSelectorID("silenced-checks"),
		datastar.WithModeInner(),
	)
}

// silencedRows loads and maps the tenant's suppressions for the settings list.
func (h *Handlers) silencedRows(
	ctx context.Context,
	p *auth.Principal,
) ([]templates.SuppressionRowView, error) {
	views, err := h.svc.SuppressionsService().ListSuppressions(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]templates.SuppressionRowView, 0, len(views))
	for _, v := range views {
		out = append(out, toSuppressionRowView(v))
	}
	return out, nil
}

// toSuppressionRowView maps a service suppression view to the settings row model.
func toSuppressionRowView(v service.SuppressionView) templates.SuppressionRowView {
	scopeText := "All domains"
	label := findingKindLabel(v.Kind) + " · " + v.IssueType
	switch v.Scope {
	case "domain":
		scopeText = v.DomainName
	case "finding":
		scopeText = v.DomainName
		label = "Finding " + v.FindingUID
	}
	return templates.SuppressionRowView{
		UID:       v.UID,
		Scope:     v.Scope,
		ScopeText: scopeText,
		State:     v.State,
		Label:     label,
		Reason:    v.Reason,
		CreatedBy: v.CreatedBy,
		Created:   v.CreatedAt,
		Expires:   v.ExpiresAt,
	}
}

// findingKindLabel resolves a kind code to its human label, falling back to the code.
func findingKindLabel(kind string) string {
	if l, ok := findingKindLabels[kind]; ok {
		return l
	}
	return kind
}

// suppressionToast maps a service sentinel error to a UI toast.
func (h *Handlers) suppressionToast(
	sse *datastar.ServerSentEventGenerator,
	err error,
	fallback string,
) {
	switch {
	case errors.Is(err, service.ErrForbidden):
		pushToast(sse, newToast("warn", "NOTICE", "Permission denied",
			"You don't have permission to manage silenced checks"))
	case errors.Is(err, service.ErrNotFound):
		pushToast(sse, newToast("warn", "NOTICE", "Not found", "It may have already been removed"))
	case errors.Is(err, service.ErrInvalidInput):
		pushToast(sse, newToast("warn", "NOTICE", "Invalid request", err.Error()))
	default:
		h.log.Error("suppression action", "error", err)
		pushToast(sse, newToast("crit", "ERROR", fallback, "please try again"))
	}
}
