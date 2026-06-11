package ui

import (
	"net/http"
	"time"

	"github.com/danielmichaels/gecko/internal/service"
	"github.com/danielmichaels/gecko/internal/ui/templates"
	"github.com/go-chi/chi/v5"
	datastar "github.com/starfederation/datastar-go/datastar"
)

// keepAliveInterval pings idle SSE streams so intermediaries (proxies, load
// balancers) do not reap a long-lived connection that is merely quiet between
// scans. It is distinct from clearing the server WriteTimeout, which stops Go
// itself from closing the connection.
const keepAliveInterval = 30 * time.Second

// coalesceInterval bounds how often a stream reacts to a burst of observations.
// An enumeration scan can write hundreds of observations in seconds; collapsing
// them into one refresh per interval keeps the UI sub-second-live without a
// flood of patches. It is the deliberate (evidence-driven) replacement for
// per-observation patching, which clashed with the grouped layout and overran
// the client.
const coalesceInterval = 750 * time.Millisecond

// coalescer collapses a burst of events into a single pending refresh: many
// mark() calls between ticks yield exactly one take()==true.
type coalescer struct{ pending bool }

func (c *coalescer) mark() { c.pending = true }

func (c *coalescer) take() bool {
	if c.pending {
		c.pending = false
		return true
	}
	return false
}

// clearStreamDeadlines removes the server's per-connection read AND write
// deadlines for a long-lived SSE response. The http.Server's WriteTimeout
// otherwise fails the next event write once it elapses; ReadTimeout is cleared
// too for defence in depth. Datastar reconnects on each drop and, after its
// retry budget, gives up — so a stale deadline silently stops live updates.
func clearStreamDeadlines(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
}

// handleDomainsStream is the live-update SSE stream for the domains list. It
// subscribes to the caller's tenant scope and, when a scan writes observations
// (or a domain is created/deleted/updated), re-renders the grouped rows of
// #domains-rows in place — the same patch handleDomainCreate uses. Renders are
// coalesced so an enumeration burst collapses to one patch per interval.
//
// The grouping/layout match the page default (nested); the in-memory TLD filter
// and search are client-only state the stream cannot see, so a live refresh
// resets to the unfiltered nested view — identical to how the create flow
// already re-renders. It patches only the rows container, never the signal-scope
// root, so it cannot re-trigger the stream opener.
func (h *Handlers) handleDomainsStream(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	clearStreamDeadlines(w)
	csrf := CSRFTokenFrom(r.Context())
	canManage := service.OwnerOrManager(p)

	sse := datastar.NewSSE(w, r)
	scope := observationScope(p.TenantID)
	subID, events := h.broker.Subscribe(scope)
	defer h.broker.Unsubscribe(scope, subID)

	var pending coalescer
	coalesce := time.NewTicker(coalesceInterval)
	defer coalesce.Stop()
	keepAlive := time.NewTicker(keepAliveInterval)
	defer keepAlive.Stop()
	var beat int

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepAlive.C:
			beat++
			if err := sse.MarshalAndPatchSignals(map[string]any{"_ka": beat}); err != nil {
				return
			}
		case <-coalesce.C:
			if !pending.take() {
				continue
			}
			rows, err := h.listDomainRows(r.Context(), p)
			if err != nil {
				h.log.Error("domains stream: list rows", "error", err)
				continue
			}
			if err := sse.PatchElementTempl(
				templates.DomainTableBody(templates.DomainsPageProps{
					Layout:  "nested",
					Domains: rows,
					Groups:  groupDomainsByApex(rows),
				}, csrf, canManage),
				datastar.WithSelectorID("domains-rows"),
				datastar.WithModeInner(),
			); err != nil {
				return
			}
		case _, ok := <-events:
			if !ok {
				return
			}
			pending.mark()
		}
	}
}

// handleDomainDetailStream is the live-update SSE stream for one domain's detail
// page. It subscribes to the caller's tenant scope and, for events matching this
// domain, re-renders the records, timeline, and findings panels (coalesced) as a
// scan writes observations. Containers for inactive tabs are present in the DOM,
// so the morph keeps whichever tab the user is viewing current. Unlike the list,
// these panels carry no client-only view state, so the server renders them
// directly.
func (h *Handlers) handleDomainDetailStream(w http.ResponseWriter, r *http.Request) {
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	uid := chi.URLParam(r, "uid")

	clearStreamDeadlines(w)

	sse := datastar.NewSSE(w, r)
	scope := observationScope(p.TenantID)
	subID, events := h.broker.Subscribe(scope)
	defer h.broker.Unsubscribe(scope, subID)

	var pending coalescer
	coalesce := time.NewTicker(coalesceInterval)
	defer coalesce.Stop()
	keepAlive := time.NewTicker(keepAliveInterval)
	defer keepAlive.Stop()
	var beat int

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepAlive.C:
			beat++
			if err := sse.MarshalAndPatchSignals(map[string]any{"_ka": beat}); err != nil {
				return
			}
		case <-coalesce.C:
			if !pending.take() {
				continue
			}
			ctx := r.Context()
			h.patchRecordsContent(ctx, sse, p, uid)
			h.patchTimelineContent(ctx, sse, p, uid)
			h.patchTimelineFullContent(ctx, sse, p, uid, "")
			h.patchFindingsContent(ctx, sse, p, uid)
		case evt, ok := <-events:
			if !ok {
				return
			}
			// Tenant scope carries every domain's events; this stream only cares
			// about the domain it is rendering.
			if evt.DomainUID == uid {
				pending.mark()
			}
		}
	}
}
