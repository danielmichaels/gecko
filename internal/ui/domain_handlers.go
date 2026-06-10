package ui

import (
	"context"
	"errors"
	"fmt"
	"html"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/dto"
	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/ui/templates"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	datastar "github.com/starfederation/datastar-go/datastar"
)

// maxListDomains bounds how many of a tenant's domains the list page fetches.
// Nested grouping, the worst-child rollups, and the TLD-filter options must be
// computed over the whole tenant set to be correct (an apex and its children can
// otherwise straddle a page boundary), so this is a generous safety bound rather
// than a display page size. Tenants beyond it are logged, not silently dropped.
const maxListDomains = 5000

// flatPageSize is how many flat-mode rows render per "load more" request. Nested
// mode is not paginated (a correct rollup needs the whole group), so this only
// bounds the flat-list DOM, not the underlying fetch.
const flatPageSize = 50

// permissionDeniedDesc is the toast body shown when a viewer attempts a domain
// mutation. The controls are hidden for viewers, so this is the backstop for a
// forged or stale request rather than the primary feedback path.
const permissionDeniedDesc = "You don't have permission to modify domains"

// handleDomainsGet renders the full domains list page.
func (h *Handlers) handleDomainsGet(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// The same route serves the full page (browser nav) and a rows-only fragment
	// (datastar search/refresh). Datastar tags its fetches with this header.
	isDatastar := r.Header.Get("Datastar-Request") == "true"

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	layout := r.URL.Query().Get("layout")
	tld := strings.TrimSpace(r.URL.Query().Get("tld"))
	offset := 0
	if isDatastar {
		var sig struct {
			Q      string `json:"q"`
			Layout string `json:"layout"`
			Tld    string `json:"tld"`
			Offset int    `json:"offset"`
		}
		if err := datastar.ReadSignals(r, &sig); err == nil {
			if query == "" {
				query = strings.TrimSpace(sig.Q)
			}
			if layout == "" {
				layout = sig.Layout
			}
			if tld == "" {
				tld = strings.TrimSpace(sig.Tld)
			}
			offset = sig.Offset
		}
	}
	// Nested is the default layout; only an explicit "flat" opts out.
	if layout != "flat" {
		layout = "nested"
	}

	result, err := h.svc.DomainsService().List(r.Context(), p, service.DomainsListParams{
		FilterName: query,
		PageSize:   maxListDomains,
		Offset:     0,
	})
	if err != nil {
		h.log.Error("domains list", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if result.TotalCount > maxListDomains {
		h.log.Warn(
			"domains list truncated: grouping/rollups cover only the fetched subset",
			"tenant", p.TenantID, "total", result.TotalCount, "cap", maxListDomains,
		)
	}

	ids := make([]int32, len(result.Domains))
	for i, d := range result.Domains {
		ids[i] = d.ID
	}
	summaries, err := h.svc.DomainsService().FindingsSummaryForPage(r.Context(), p, ids)
	if err != nil {
		h.log.Error("domains list: findings summary", "error", err)
		summaries = nil
	}
	recordCounts, err := h.svc.DomainsService().RecordCountsForPage(r.Context(), p, ids)
	if err != nil {
		h.log.Error("domains list: record counts", "error", err)
		recordCounts = nil
	}

	rows := make([]templates.DomainRowView, len(result.Domains))
	for i, d := range result.Domains {
		view := domainRowView(d)
		view.RecordCount = strconv.Itoa(int(recordCounts[d.ID]))
		if sum, ok := summaries[d.ID]; ok {
			view.FindingsSeverity, view.FindingsLabel = findingBadge(sum)
		}
		rows[i] = view
	}

	// TLD options reflect every apex present (computed before the filter narrows
	// rows). The active filter then scopes the rendered rows to one apex family.
	tldOptions := distinctApexes(rows)
	if tld != "" {
		filtered := make([]templates.DomainRowView, 0, len(rows))
		for _, row := range rows {
			if apexOf(row.Name) == tld {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	groups := groupDomainsByApex(rows)

	if isDatastar {
		sse := datastar.NewSSE(w, r)
		csrf := CSRFTokenFrom(r.Context())
		canManage := service.OwnerOrManager(p)
		if layout == "flat" {
			// DOM pagination over the in-memory filtered set: offset 0 replaces the
			// list, a later offset appends the next page. The offset signal is
			// advanced server-side so the load-more button stays stateless.
			start := offset
			if start < 0 {
				start = 0
			}
			if start > len(rows) {
				start = len(rows)
			}
			end := start + flatPageSize
			if end > len(rows) {
				end = len(rows)
			}
			page := rows[start:end]
			mode := datastar.WithModeInner()
			if start > 0 {
				mode = datastar.WithModeAppend()
			}
			if start == 0 || len(page) > 0 {
				_ = sse.PatchElementTempl(
					templates.DomainRowsFragment(page, csrf, canManage),
					datastar.WithSelectorID("domains-rows"),
					mode,
				)
			}
			_ = sse.PatchElementTempl(
				templates.DomainsLoadMore(end < len(rows)),
				datastar.WithSelectorID("domains-more"),
			)
			_ = sse.MarshalAndPatchSignals(map[string]any{"offset": end})
		} else {
			_ = sse.PatchElementTempl(
				templates.DomainTableBody(templates.DomainsPageProps{
					Layout:  layout,
					Domains: rows,
					Groups:  groups,
				}, csrf, canManage),
				datastar.WithSelectorID("domains-rows"),
				datastar.WithModeInner(),
			)
			_ = sse.PatchElementTempl(
				templates.DomainsLoadMore(false),
				datastar.WithSelectorID("domains-more"),
			)
		}
		_ = sse.PatchElements(
			fmt.Sprintf(
				`<div class="result-meta" id="result-meta">%s</div>`,
				resultMeta(int(result.TotalCount), query),
			),
			datastar.WithSelectorID("result-meta"),
		)
		return
	}

	// Tenant-wide rollups are served from the tenant_stats cache (refreshed off
	// the request path by the RefreshTenantStats job). Before the job's first run
	// the row is absent, so we fall back to placeholders.
	tenantStats, err := h.svc.DomainsService().TenantStats(r.Context(), p)
	if err != nil {
		h.log.Error("domains list: tenant stats", "error", err)
	}
	stats := templates.DomainsStats{
		Tracked:  strconv.FormatInt(result.TotalCount, 10),
		Critical: "0",
		Warnings: "0",
		Records:  "—",
	}
	if tenantStats.Present {
		stats.Critical = strconv.Itoa(int(tenantStats.CriticalCount))
		stats.Warnings = strconv.Itoa(int(tenantStats.WarningCount))
		stats.Records = strconv.FormatInt(tenantStats.RecordTotal, 10)
	}

	shell, err := h.shell(r.Context(), "domains")
	if err != nil {
		h.log.Error("domains: build shell", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	renderPage(w, r, templates.DomainsPage(templates.DomainsPageProps{
		Shell:      shell,
		Stats:      stats,
		Layout:     layout,
		Domains:    rows,
		Groups:     groups,
		TLDOptions: tldOptions,
	}))
}

// listDomainRows lists a tenant's domains (capped at the page size) and maps
// them to row views, overlaying each domain's open-findings badge. Shared by the
// list page and the create flow so both render the same row data.
func (h *Handlers) listDomainRows(
	ctx context.Context,
	p *auth.Principal,
) ([]templates.DomainRowView, error) {
	result, err := h.svc.DomainsService().List(ctx, p, service.DomainsListParams{
		PageSize: maxListDomains,
		Offset:   0,
	})
	if err != nil {
		return nil, err
	}

	ids := make([]int32, len(result.Domains))
	for i, d := range result.Domains {
		ids[i] = d.ID
	}
	summaries, err := h.svc.DomainsService().FindingsSummaryForPage(ctx, p, ids)
	if err != nil {
		h.log.Error("domains list: findings summary", "error", err)
		summaries = nil
	}
	recordCounts, err := h.svc.DomainsService().RecordCountsForPage(ctx, p, ids)
	if err != nil {
		h.log.Error("domains list: record counts", "error", err)
		recordCounts = nil
	}

	rows := make([]templates.DomainRowView, len(result.Domains))
	for i, d := range result.Domains {
		view := domainRowView(d)
		view.RecordCount = strconv.Itoa(int(recordCounts[d.ID]))
		if sum, ok := summaries[d.ID]; ok {
			view.FindingsSeverity, view.FindingsLabel = findingBadge(sum)
		}
		rows[i] = view
	}
	return rows, nil
}

// resultMeta renders the count line under the search bar: the tenant total, or
// the match count for an active query (query echoed back, HTML-escaped).
func resultMeta(total int, query string) string {
	if query == "" {
		return fmt.Sprintf("%d domains", total)
	}
	return fmt.Sprintf("%d matching “%s”", total, html.EscapeString(query))
}

// handleDomainCreate adds a new domain via a datastar SSE POST.
// The addbar input is bound to the "newDomain" signal.
func (h *Handlers) handleDomainCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var form struct {
		NewDomain string `json:"newDomain"`
	}
	if err := datastar.ReadSignals(r, &form); err != nil {
		h.log.Error("domain create: read signals", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	sse := datastar.NewSSE(w, r)

	_, err := h.svc.DomainsService().Create(r.Context(), p, service.DomainsCreateParams{
		Domain: form.NewDomain,
	})
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			pushToast(sse, newToast("warn", "NOTICE", "Permission denied", permissionDeniedDesc))
			return
		}
		if errors.Is(err, service.ErrConflict) {
			pushToast(sse, newToast("warn", "NOTICE", "Domain already tracked", form.NewDomain))
			return
		}
		h.log.Error("domain create", "error", err)
		pushToast(sse, newToast("crit", "ERROR", "Failed to add domain", form.NewDomain))
		return
	}

	// A flat append would drop the new subdomain ungrouped at the bottom, so
	// re-render the whole grouped body to nest it under its apex.
	rows, err := h.listDomainRows(r.Context(), p)
	if err != nil {
		h.log.Error("domain create: re-list", "error", err)
		pushToast(
			sse,
			newToast("warn", "NOTICE", "Domain added", "added, but the list failed to refresh"),
		)
		return
	}

	_ = sse.PatchElementTempl(
		templates.DomainTableBody(templates.DomainsPageProps{
			Layout:  "nested",
			Domains: rows,
			Groups:  groupDomainsByApex(rows),
		}, CSRFTokenFrom(r.Context()), service.OwnerOrManager(p)),
		datastar.WithSelectorID("domains-rows"),
		datastar.WithModeInner(),
	)
	// The grouped body is the full set; drop any flat load-more trigger left over
	// from flat mode so it can't append a stale page on top of the groups.
	_ = sse.PatchElementTempl(
		templates.DomainsLoadMore(false),
		datastar.WithSelectorID("domains-more"),
	)
	pushToast(sse, newToast("ok", "DOMAIN", "Domain added", form.NewDomain+" is now tracked"))
	// Close the drawer and reset its input.
	_ = sse.MarshalAndPatchSignals(map[string]any{"drawerOpen": false, "newDomain": ""})
}

// handleDomainDelete removes a domain via a datastar SSE DELETE.
func (h *Handlers) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")
	sse := datastar.NewSSE(w, r)

	err := h.svc.DomainsService().Delete(r.Context(), p, uid)
	if errors.Is(err, service.ErrForbidden) {
		// Leave the row in place; the viewer never had permission to remove it.
		pushToast(sse, newToast("warn", "NOTICE", "Permission denied", permissionDeniedDesc))
		return
	}
	if err != nil && !errors.Is(err, service.ErrNotFound) {
		h.log.Error("domain delete", "error", err, "uid", uid)
	}

	// Remove the row regardless (idempotent: a 404 just means it's already gone).
	_ = sse.RemoveElementByID("domain-row-" + uid)
}

// handleDomainDetail renders the domain detail full page.
// The page lazy-loads records and timeline panels via intersect events.
func (h *Handlers) handleDomainDetail(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")

	d, err := h.svc.DomainsService().Get(r.Context(), p, uid)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			http.Redirect(w, r, "/app/domains", http.StatusSeeOther)
			return
		}
		h.log.Error("domain detail: get", "error", err, "uid", uid)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	shell, err := h.shell(r.Context(), "domains")
	if err != nil {
		h.log.Error("domain detail: build shell", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	added := "—"
	if d.CreatedAt.Valid {
		added = d.CreatedAt.Time.Format("2006-01-02")
	}

	findingsCount := "0"
	findingsSeverity := "ok"
	if sums, sErr := h.svc.DomainsService().FindingsSummaryForPage(r.Context(), p, []int32{d.ID}); sErr != nil {
		h.log.Error("domain detail: findings summary", "error", sErr, "uid", uid)
	} else if sum, ok := sums[d.ID]; ok && sum.Count > 0 {
		findingsCount = strconv.Itoa(int(sum.Count))
		findingsSeverity, _ = findingBadge(sum)
	}

	var recordCount string
	if counts, cErr := h.svc.DomainsService().RecordCountsForPage(r.Context(), p, []int32{d.ID}); cErr != nil {
		h.log.Error("domain detail: record counts", "error", cErr, "uid", uid)
		recordCount = "—"
	} else {
		recordCount = strconv.Itoa(int(counts[d.ID]))
	}

	// Deep-link target from the Scans feed: ?tab=timeline&scan=… opens the
	// Timeline tab and highlights the targeted scan. Only "timeline" is honored;
	// any other value falls back to the default Records tab.
	initialTab := "records"
	if r.URL.Query().Get("tab") == "timeline" {
		initialTab = "timeline"
	}

	renderPage(w, r, templates.DomainDetailPage(templates.DomainDetailPageProps{
		Shell:            shell,
		UID:              d.Uid,
		Name:             d.Name,
		Severity:         severityForStatus(d.Status),
		RecordCount:      recordCount,
		FindingsCount:    findingsCount,
		FindingsSeverity: findingsSeverity,
		Type:             string(d.DomainType),
		Source:           string(d.Source),
		Added:            added,
		Scanned:          relativeTime(d.UpdatedAt),
		InitialTab:       initialTab,
		InitialScan:      strings.TrimSpace(r.URL.Query().Get("scan")),
	}))
}

// handleRecordsFragment lazy-loads DNS records into the records panel.
func (h *Handlers) handleRecordsFragment(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")
	sse := datastar.NewSSE(w, r)

	result, err := h.svc.RecordsService().List(r.Context(), p, uid, nil)
	if err != nil {
		retryURL := fmt.Sprintf("/app/domains/%s/records", uid)
		msg := "failed to load records"
		if errors.Is(err, service.ErrNotFound) {
			msg = "domain not found"
		}
		_ = sse.PatchElementTempl(
			templates.ContentError(templates.ContentErrorProps{Message: msg, RetryURL: retryURL}),
			datastar.WithSelectorID("records-content"),
			datastar.WithModeInner(),
		)
		return
	}

	rows := recordRows(result.Records)

	// Build a summary of record types present for the count label.
	typeSummary := recordTypeSummary(result.Records)
	count := strconv.FormatInt(result.TotalRecords, 10)
	if typeSummary != "" {
		count = count + " · " + typeSummary
	}

	view := templates.RecordsView{
		Title: "DNS records",
		Count: count,
		Rows:  rows,
	}

	_ = sse.PatchElementTempl(
		templates.RecordsTable(view),
		datastar.WithSelectorID("records-content"),
		datastar.WithModeInner(),
	)
}

// handleTimelineFragment lazy-loads the scan timeline into the timeline panel.
func (h *Handlers) handleTimelineFragment(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")
	sse := datastar.NewSSE(w, r)

	result, err := h.svc.RecordsService().Timeline(r.Context(), p, uid)
	if err != nil {
		retryURL := fmt.Sprintf("/app/domains/%s/timeline", uid)
		msg := "failed to load timeline"
		if errors.Is(err, service.ErrNotFound) {
			msg = "domain not found"
		}
		_ = sse.PatchElementTempl(
			templates.ContentError(templates.ContentErrorProps{Message: msg, RetryURL: retryURL}),
			datastar.WithSelectorID("timeline-content"),
			datastar.WithModeInner(),
		)
		return
	}

	items := timelineItems(result.Scans)

	_ = sse.PatchElementTempl(
		templates.Timeline(templates.TimelineView{Groups: items}),
		datastar.WithSelectorID("timeline-content"),
		datastar.WithModeInner(),
	)
}

// handleTimelineFullFragment lazy-loads the full-width Timeline tab (loaded on
// first click of the tab). Reuses the same scan-grouped data as the side panel.
func (h *Handlers) handleTimelineFullFragment(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")
	sse := datastar.NewSSE(w, r)

	result, err := h.svc.RecordsService().Timeline(r.Context(), p, uid)
	if err != nil {
		msg := "failed to load timeline"
		if errors.Is(err, service.ErrNotFound) {
			msg = "domain not found"
		}
		_ = sse.PatchElementTempl(
			templates.ContentError(templates.ContentErrorProps{
				Message:  msg,
				RetryURL: fmt.Sprintf("/app/domains/%s/timeline/full", uid),
			}),
			datastar.WithSelectorID("timeline-full-content"),
			datastar.WithModeInner(),
		)
		return
	}

	highlightScan := strings.TrimSpace(r.URL.Query().Get("scan"))
	_ = sse.PatchElementTempl(
		templates.TimelineFull(timelineFullView(result.Scans, highlightScan)),
		datastar.WithSelectorID("timeline-full-content"),
		datastar.WithModeInner(),
	)
}

// handleFindingsFragment lazy-loads the Findings tab (loaded on first click).
func (h *Handlers) handleFindingsFragment(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")
	sse := datastar.NewSSE(w, r)

	result, err := h.svc.FindingsService().ListByDomain(r.Context(), p, uid)
	if err != nil {
		msg := "failed to load findings"
		if errors.Is(err, service.ErrNotFound) {
			msg = "domain not found"
		}
		_ = sse.PatchElementTempl(
			templates.ContentError(templates.ContentErrorProps{
				Message:  msg,
				RetryURL: fmt.Sprintf("/app/domains/%s/findings", uid),
			}),
			datastar.WithSelectorID("findings-content"),
			datastar.WithModeInner(),
		)
		return
	}

	_ = sse.PatchElementTempl(
		templates.FindingsPanel(toFindingsView(result)),
		datastar.WithSelectorID("findings-content"),
		datastar.WithModeInner(),
	)
}

// handleDomainRescan triggers a rescan for a single domain.
// It forces a re-scan via Update (empty params = keep fields, just rescan).
// NOTE: this endpoint is called from the detail page where no #domain-row-{uid}
// exists, so we cannot patch a row — v1 gives no inline feedback; the list page
// reflects the updated state on the next load.
func (h *Handlers) handleDomainRescan(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	uid := chi.URLParam(r, "uid")

	// Call Update BEFORE opening the SSE stream so we can still write an HTTP
	// error status if the request fails (once SSE headers are flushed, status
	// codes are discarded by the browser).
	d, err := h.svc.DomainsService().Update(r.Context(), p, uid, service.DomainsUpdateParams{})
	if err != nil {
		sse := datastar.NewSSE(w, r)
		if errors.Is(err, service.ErrForbidden) {
			pushToast(sse, newToast("warn", "NOTICE", "Permission denied", permissionDeniedDesc))
			return
		}
		if errors.Is(err, service.ErrNotFound) {
			pushToast(sse, newToast("warn", "NOTICE", "Domain not found", "nothing to rescan"))
			return
		}
		h.log.Error("domain rescan", "error", err, "uid", uid)
		pushToast(
			sse,
			newToast("crit", "ERROR", "Rescan failed", "resolver degraded — try again shortly"),
		)
		return
	}

	// Open SSE only on the success path. The detail page has no #domain-row-{uid}
	// to patch, so the toast is the sole confirmation; the list page reflects the
	// scanning state on the next visit.
	sse := datastar.NewSSE(w, r)
	pushToast(sse, newToast("ok", "SCAN", "Rescan queued", d.Name+" · enumerating"))
}

// handleDomainsRescanAll triggers a rescan for every tracked domain (bounded to
// the first 100 — same as the list page). Each Update enqueues a scan.
func (h *Handlers) handleDomainsRescanAll(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	result, err := h.svc.DomainsService().List(r.Context(), p, service.DomainsListParams{
		PageSize: 100,
		Offset:   0,
	})
	if err != nil {
		h.log.Error("domains rescan all: list", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	sse := datastar.NewSSE(w, r)

	csrfToken := CSRFTokenFrom(r.Context())
	queued := 0
	for _, d := range result.Domains {
		updated, uErr := h.svc.DomainsService().
			Update(r.Context(), p, d.Uid, service.DomainsUpdateParams{})
		if errors.Is(uErr, service.ErrForbidden) {
			// Role is per-principal, not per-domain: the first rejection means every
			// rescan would be rejected. Stop and surface a single toast.
			pushToast(sse, newToast("warn", "NOTICE", "Permission denied", permissionDeniedDesc))
			return
		}
		if uErr != nil {
			h.log.Warn("domains rescan all: update", "error", uErr, "uid", d.Uid)
			continue
		}
		queued++
		view := domainRowView(updated)
		view.Severity = "scan"
		view.FindingsLabel = "scanning"
		view.FindingsSeverity = "info"

		_ = sse.PatchElementTempl(
			templates.DomainRow(view, csrfToken, service.OwnerOrManager(p)),
			datastar.WithSelectorID("domain-row-"+d.Uid),
		)
	}

	pushToast(sse, newToast("info", "SCAN", "Fleet rescan started",
		strconv.Itoa(queued)+" domains queued for enumeration"))
}

// ── helpers ──────────────────────────────────────────────────────────────────

// domainRowView maps a store.Domains to the presentation model.
func domainRowView(d store.Domains) templates.DomainRowView {
	return templates.DomainRowView{
		UID:  d.Uid,
		Name: d.Name,
		// RecordCount defaults to "—"; list/detail handlers override it from the
		// index-driven per-page record-count query.
		RecordCount: "—",
		Severity:    severityForStatus(d.Status),
		// v1 placeholders: findings subsystem not yet implemented.
		FindingsLabel:    "healthy",
		FindingsSeverity: "ok",
		LastScan:         relativeTime(d.UpdatedAt),
	}
}

// findingBadge maps an open-findings aggregate to a row badge (CSS class + label).
// Worst severity drives the colour; info-only and no-findings both read "healthy".
func findingBadge(sum service.DomainFindingSummary) (severity, label string) {
	switch {
	case sum.SeverityRank <= 2:
		return "crit", "critical"
	case sum.SeverityRank == 3 || sum.SeverityRank == 4:
		return "warn", "warning"
	default:
		return "ok", "healthy"
	}
}

// severityForStatus maps a domain status to the CSS severity class used in the UI.
func severityForStatus(s store.DomainStatus) string {
	switch s {
	case store.DomainStatusPending:
		return "scan"
	default:
		return "ok"
	}
}

// relativeTime converts a pgtype.Timestamptz to a human-readable relative string
// such as "2h ago" or "3d ago". Returns "—" if the timestamp is not valid.
func relativeTime(t pgtype.Timestamptz) string {
	if !t.Valid {
		return "—"
	}
	d := time.Since(t.Time)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(math.Round(d.Minutes()))) + "m ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(math.Round(d.Hours()))) + "h ago"
	case d < 7*24*time.Hour:
		return strconv.Itoa(int(math.Round(d.Hours()/24))) + "d ago"
	default:
		return t.Time.Format("2006-01-02")
	}
}

// recordRows flattens dto.AllRecords into a slice of RecordRowView.
func recordRows(all dto.AllRecords) []templates.RecordRowView {
	var rows []templates.RecordRowView

	for _, r := range all.A {
		rows = append(rows, templates.RecordRowView{Type: "A", Value: r.IPv4Address})
	}
	for _, r := range all.AAAA {
		rows = append(rows, templates.RecordRowView{Type: "AAAA", Value: r.IPv6Address})
	}
	for _, r := range all.CNAME {
		rows = append(rows, templates.RecordRowView{Type: "CNAME", Value: r.Target})
	}
	for _, r := range all.MX {
		rows = append(rows, templates.RecordRowView{
			Type:  "MX",
			Value: fmt.Sprintf("%d %s", r.Preference, r.Target),
		})
	}
	for _, r := range all.TXT {
		rows = append(rows, templates.RecordRowView{Type: "TXT", Value: r.Value})
	}
	for _, r := range all.NS {
		rows = append(rows, templates.RecordRowView{Type: "NS", Value: r.Nameserver})
	}
	for _, r := range all.SOA {
		rows = append(rows, templates.RecordRowView{Type: "SOA", Value: r.Nameserver})
	}
	for _, r := range all.PTR {
		rows = append(rows, templates.RecordRowView{Type: "PTR", Value: r.Target})
	}
	for _, r := range all.CAA {
		rows = append(rows, templates.RecordRowView{
			Type:  "CAA",
			Value: fmt.Sprintf("%s %s", r.Tag, r.Value),
		})
	}
	for _, r := range all.SRV {
		rows = append(rows, templates.RecordRowView{Type: "SRV", Value: r.Target})
	}
	for _, r := range all.DNSKEY {
		key := r.PublicKey
		if len(key) > 40 {
			key = key[:40] + "…"
		}
		rows = append(rows, templates.RecordRowView{Type: "DNSKEY", Value: key})
	}
	for _, r := range all.DS {
		rows = append(rows, templates.RecordRowView{Type: "DS", Value: r.Digest})
	}
	for _, r := range all.RRSIG {
		rows = append(rows, templates.RecordRowView{Type: "RRSIG", Value: r.SignerName})
	}

	return rows
}

// recordTypeSummary builds a compact label of which record types are present.
func recordTypeSummary(all dto.AllRecords) string {
	var parts []string
	if len(all.A) > 0 {
		parts = append(parts, fmt.Sprintf("%d A", len(all.A)))
	}
	if len(all.AAAA) > 0 {
		parts = append(parts, fmt.Sprintf("%d AAAA", len(all.AAAA)))
	}
	if len(all.CNAME) > 0 {
		parts = append(parts, fmt.Sprintf("%d CNAME", len(all.CNAME)))
	}
	if len(all.MX) > 0 {
		parts = append(parts, fmt.Sprintf("%d MX", len(all.MX)))
	}
	if len(all.TXT) > 0 {
		parts = append(parts, fmt.Sprintf("%d TXT", len(all.TXT)))
	}
	if len(all.NS) > 0 {
		parts = append(parts, fmt.Sprintf("%d NS", len(all.NS)))
	}
	if len(all.SOA) > 0 {
		parts = append(parts, fmt.Sprintf("%d SOA", len(all.SOA)))
	}
	if len(all.PTR) > 0 {
		parts = append(parts, fmt.Sprintf("%d PTR", len(all.PTR)))
	}
	if len(all.CAA) > 0 {
		parts = append(parts, fmt.Sprintf("%d CAA", len(all.CAA)))
	}
	if len(all.SRV) > 0 {
		parts = append(parts, fmt.Sprintf("%d SRV", len(all.SRV)))
	}
	if len(all.DNSKEY) > 0 {
		parts = append(parts, fmt.Sprintf("%d DNSKEY", len(all.DNSKEY)))
	}
	if len(all.DS) > 0 {
		parts = append(parts, fmt.Sprintf("%d DS", len(all.DS)))
	}
	if len(all.RRSIG) > 0 {
		parts = append(parts, fmt.Sprintf("%d RRSIG", len(all.RRSIG)))
	}
	return strings.Join(parts, " ")
}

// timelineItems flattens []dto.ScanDiff into a flat []TimelineItemView.
// Each scan emits a header item followed by one item per change.
func timelineItems(scans []dto.ScanDiff) []templates.TimelineItemView {
	var items []templates.TimelineItemView

	for _, scan := range scans {
		shortUID := scan.ScanUID
		if len(shortUID) > 8 {
			shortUID = shortUID[:8]
		}

		when := scan.StartedAt
		if t, err := time.Parse(time.RFC3339, scan.StartedAt); err == nil {
			when = t.Format("2006-01-02 15:04")
		}

		items = append(items, templates.TimelineItemView{
			Kind: "scan",
			When: when,
			What: fmt.Sprintf("Scan %s · %d change(s)", shortUID, len(scan.Changes)),
		})

		for _, ch := range scan.Changes {
			chWhen := ch.ObservedAt
			if t, err := time.Parse(time.RFC3339, ch.ObservedAt); err == nil {
				chWhen = t.Format("2006-01-02 15:04")
			}

			var prefix, kind string
			switch ch.ChangeType {
			case "created":
				prefix = "+"
				kind = "add"
			case "deleted":
				prefix = "−"
				kind = "del"
			default:
				prefix = "~"
				kind = "chg"
			}

			items = append(items, templates.TimelineItemView{
				Kind: kind,
				When: chWhen,
				What: fmt.Sprintf("%s %s %s", prefix, ch.EntityType, ch.EntityKey),
			})
		}
	}

	return items
}

// changeGlyph maps an observation change_type to a diff glyph + CSS kind.
func changeGlyph(changeType string) (op, kind string) {
	switch changeType {
	case "created":
		return "+", "add"
	case "deleted":
		return "−", "del"
	default:
		return "~", "chg"
	}
}

// timelineFullView maps []dto.ScanDiff into the full-width Timeline tab model.
// highlightUID marks the scan a /app/scans deep-link targeted (empty = none).
func timelineFullView(scans []dto.ScanDiff, highlightUID string) templates.TimelineFullView {
	groups := make([]templates.ScanGroupView, 0, len(scans))
	totalChanges := 0

	for _, scan := range scans {
		when := scan.StartedAt
		if t, err := time.Parse(time.RFC3339, scan.StartedAt); err == nil {
			when = t.Format("2006-01-02 15:04")
		}

		changes := make([]templates.ChangeView, len(scan.Changes))
		for i, ch := range scan.Changes {
			op, kind := changeGlyph(ch.ChangeType)
			changes[i] = templates.ChangeView{
				Kind:   kind,
				Op:     op,
				Entity: ch.EntityType,
				Value:  ch.EntityKey,
			}
		}
		totalChanges += len(scan.Changes)

		groups = append(groups, templates.ScanGroupView{
			ScanID:      scan.ScanUID,
			When:        when,
			Meta:        scan.Source,
			ChangeCount: len(scan.Changes),
			Changes:     changes,
			Highlighted: highlightUID != "" && scan.ScanUID == highlightUID,
		})
	}

	return templates.TimelineFullView{
		ScanCount:   len(scans),
		ChangeCount: totalChanges,
		Groups:      groups,
	}
}

// toFindingsView maps a service.FindingsResult into the Findings tab model.
func toFindingsView(r service.FindingsResult) templates.FindingsView {
	cards := make([]templates.FindingCardView, len(r.Findings))
	for i, f := range r.Findings {
		cards[i] = templates.FindingCardView{
			SevClass:    f.SevClass,
			Severity:    f.Severity,
			Icon:        f.Icon,
			Title:       f.Title,
			Description: f.Description,
			Evidence:    f.Evidence,
			FixHint:     f.FixHint,
		}
	}
	return templates.FindingsView{
		TotalCount:    r.TotalCount,
		CriticalCount: r.CriticalCount,
		WarningCount:  r.WarningCount,
		HealthyCount:  r.HealthyCount,
		Findings:      cards,
	}
}
