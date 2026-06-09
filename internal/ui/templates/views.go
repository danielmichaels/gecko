package templates

import "fmt"

// postWithCSRF returns a datastar data-on-click action string that POSTs to url
// carrying the CSRF token in the X-CSRF-Token header.
// Pattern used on every state-mutating datastar action.
func postWithCSRF(url, token string) string {
	return fmt.Sprintf("@post('%s', {headers: {'X-CSRF-Token': '%s'}})", url, token)
}

// postWithConfirm returns a data-on-click action that confirms before POSTing to
// url with the CSRF token. Used for bulk/irreversible actions like rescan-all.
func postWithConfirm(message, url, token string) string {
	return fmt.Sprintf(
		"if(!confirm('%s')) return; @post('%s', {headers: {'X-CSRF-Token': '%s'}})",
		message,
		url,
		token,
	)
}

// deleteRowWithConfirm returns a data-on-click action that confirms before deleting.
func deleteRowWithConfirm(url, token string) string {
	return fmt.Sprintf(
		"evt.stopPropagation(); if(!confirm('Delete this domain?')) return; @delete('%s', {headers: {'X-CSRF-Token': '%s'}})",
		url,
		token,
	)
}

// inviteSignals returns a JSON signals string for the invite form.
func inviteSignals(token string) string {
	return fmt.Sprintf(`{"token":"%s","password":"","name":""}`, token)
}

// toggleCollapse returns a datastar expression that toggles an apex key in the
// $collapsed array signal. A single array signal is used because datastar
// signals are a fixed object — per-group keys are not dynamically addable.
func toggleCollapse(apex string) string {
	return fmt.Sprintf(
		"$collapsed = $collapsed.includes('%s') ? $collapsed.filter(k => k !== '%s') : [...$collapsed, '%s']",
		apex,
		apex,
		apex,
	)
}

// notCollapsed returns a datastar expression true when the apex is expanded.
func notCollapsed(apex string) string { return fmt.Sprintf("!$collapsed.includes('%s')", apex) }

// collapsedClass returns a datastar data-class map toggling 'collapsed' on the apex row.
func collapsedClass(apex string) string {
	return fmt.Sprintf("{'collapsed': $collapsed.includes('%s')}", apex)
}

// subLabel renders the "N sub" pill text for an apex group.
func subLabel(n int) string { return fmt.Sprintf("%d sub", n) }

// childLabel strips the apex suffix from a child FQDN, leaving the label that
// renders bold ("api" from "api.example.com"). Falls back to the full name.
func childLabel(name, apex string) string {
	if suffix := "." + apex; len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
		return name[:len(name)-len(suffix)]
	}
	return name
}

// dotClass maps a rollup severity to its single-letter CSS class for the dots.
func dotClass(sev string) string {
	switch sev {
	case "crit":
		return "c"
	case "warn":
		return "w"
	case "scan":
		return "s"
	default:
		return "o"
	}
}

// AppShellProps contains the data needed to render the application shell:
// topbar, sidebar navigation, and the authenticated user context.
type AppShellProps struct {
	TenantName   string
	UserEmail    string
	UserInitials string
	ActiveNav    string
	AppVersion   string
	CSRFToken    string
	ResolverOK   bool
}

// LoginPageProps holds data for the login page.
type LoginPageProps struct {
	CSRFToken string
	Error     string
}

// AcceptInvitePageProps holds data for the accept-invitation page.
type AcceptInvitePageProps struct {
	CSRFToken    string
	Token        string
	TenantName   string
	InviterEmail string
	Role         string
	InviteeEmail string
	Expiry       string
	Error        string
}

// DomainsStats holds the four stat-strip values for the domains list page.
type DomainsStats struct {
	Tracked  string
	Critical string
	Warnings string
	Records  string
}

// DomainsPageProps holds data for the domains list page.
type DomainsPageProps struct {
	Shell      AppShellProps
	Stats      DomainsStats
	Domains    []DomainRowView
	Layout     string
	Groups     []DomainGroupView
	TLDOptions []string
}

// DomainGroupView is the presentation model for one apex group in nested layout:
// the apex header (real or synthetic) plus its subdomain children, with a
// worst-child severity rollup.
type DomainGroupView struct {
	Header           DomainRowView
	Apex             string
	RollupSeverity   string // worst severity across header+children
	FindingsSeverity string // apex badge CSS class (crit|warn|ok|info)
	FindingsLabel    string // apex badge text, e.g. "1 critical" / "clean"
	Children         []DomainRowView
	Rollup           []string // distinct severities present, worst-first
	SubCount         int
	HasOwn           bool
}

// DomainRowView is the presentation model for a single row in the domain table.
type DomainRowView struct {
	UID              string
	Name             string
	Severity         string
	RecordCount      string
	FindingsLabel    string
	FindingsSeverity string
	LastScan         string
}

// DomainDetailPageProps holds data for the domain detail page.
type DomainDetailPageProps struct {
	UID              string
	Name             string
	Severity         string
	RecordCount      string
	FindingsCount    string
	FindingsSeverity string // crit | warn | ok — colours the findings badge/tab
	Type             string
	Source           string
	Added            string
	Scanned          string
	// InitialTab/InitialScan drive deep-links from the Scans feed: opening the
	// page at ?tab=timeline&scan=… auto-selects the Timeline tab and highlights
	// the targeted scan. InitialTab defaults to "records".
	InitialTab  string
	InitialScan string
	Shell       AppShellProps
}

// RecordRowView is the presentation model for one DNS record row.
type RecordRowView struct {
	Type    string
	Value   string
	TTL     string
	Flagged bool
}

// RecordsView is the lazy-loaded fragment for the records panel.
type RecordsView struct {
	Title string
	Count string
	Rows  []RecordRowView
}

// TimelineItemView is the presentation model for a single timeline entry.
type TimelineItemView struct {
	Kind string
	When string
	What string
}

// TimelineView is the lazy-loaded fragment for the timeline panel.
type TimelineView struct {
	Groups []TimelineItemView
}

// ChangeView is one add/remove/change row in the full Timeline tab.
type ChangeView struct {
	Kind   string // add | del | chg
	Op     string // + | − | ~
	Entity string
	Value  string
}

// ScanGroupView groups one scan's changes in the full Timeline tab. Highlighted
// marks the scan that a /app/scans deep-link (?scan=) targeted, so it renders with
// an accent border.
type ScanGroupView struct {
	ScanID      string
	When        string
	Meta        string
	Changes     []ChangeView
	ChangeCount int
	Highlighted bool
}

// TimelineFullView is the lazy-loaded fragment for the full-width Timeline tab.
type TimelineFullView struct {
	Groups      []ScanGroupView
	ScanCount   int
	ChangeCount int
}

// FindingCardView is one security finding rendered as a card.
type FindingCardView struct {
	SevClass    string
	Severity    string
	Icon        string
	Title       string
	Description string
	Evidence    string
	FixHint     string
}

// FindingsView is the lazy-loaded fragment for the Findings tab.
type FindingsView struct {
	Findings      []FindingCardView
	TotalCount    int
	CriticalCount int
	WarningCount  int
	HealthyCount  int
}

// FindingsPageProps holds data for the tenant-wide Findings page.
type FindingsPageProps struct {
	Shell AppShellProps
	View  TenantFindingsView
}

// TenantFindingsView is the presentation model for the whole Findings screen:
// the stat strip, the data-driven filter controls, and the grouped rows. It is
// re-rendered as a fragment (#findings-list) on every filter change.
type TenantFindingsView struct {
	SevCounts   map[string]int // tier (crit|high|med|low) -> faceted chip count
	Groups      []FindingGroupView
	KindOptions []FindingKindOption
	OpenCount   int
	DomainCount int
	CritCount   int
	HighCount   int
	MedCount    int
}

// FindingKindOption is one entry in the data-driven type dropdown.
type FindingKindOption struct {
	Value string // SPF | DKIM | DMARC | ZONE
	Label string
	Count int
}

// FindingGroupView is one domain's collapsible group: a dimmed-apex name, a
// rollup seg-bar + pills, and its finding rows.
type FindingGroupView struct {
	DomainUID  string
	Name       string // full domain name, used as the collapse key
	Label      string // bold leading label
	ApexSuffix string // dimmed apex suffix (".example.org"), empty for an apex
	CountLabel string // "3 findings"
	Segments   []FindingSegment
	Pills      []FindingPill
	Findings   []FindingRowView
}

// FindingSegment is one proportional slice of a group's rollup bar.
type FindingSegment struct {
	Class string // c | h | m | l
	Width string // e.g. "66%"
}

// FindingPill is one per-tier count chip on a group header.
type FindingPill struct {
	Class string // c | h | m | l
	Glyph string // ● | ▲
	Count int
}

// FindingRowView is one finding: a collapsed line plus an expandable detail card.
type FindingRowView struct {
	FindingUID  string
	DomainUID   string
	Tier        string // crit | high | med | low | ok (CSS class)
	Severity    string // "critical" | "high" | ... (label text)
	Kind        string
	Icon        string
	Title       string
	Description string
	Evidence    string
	FixHint     string
	FirstSeen   string
}

// findingOpen returns the datastar expression that flips a finding's membership
// in the $open array (inline expand, zero round-trip).
func findingOpen(uid string) string {
	return fmt.Sprintf(
		"$open = $open.includes('%s') ? $open.filter(k => k !== '%s') : [...$open, '%s']",
		uid, uid, uid,
	)
}

// findingOpenClass toggles the 'open' class on a finding row when it is expanded.
func findingOpenClass(uid string) string {
	return fmt.Sprintf("{'open': $open.includes('%s')}", uid)
}

// sevToggle single-selects a severity tier: clicking the active chip clears it.
// Re-fetches the list so the server applies the new filter.
func sevToggle(sev string) string {
	return fmt.Sprintf("$sev = $sev === '%s' ? '' : '%s'; @get('/app/findings')", sev, sev)
}

// sevChipClass marks a severity chip active when it is the selected tier.
func sevChipClass(sev string) string { return fmt.Sprintf("{'on': $sev === '%s'}", sev) }

// ScansPageProps holds data for the tenant-wide Scans page.
type ScansPageProps struct {
	Shell AppShellProps
	View  TenantScansView
}

// TenantScansView is the presentation model for the whole Scans screen: the stat
// strip, the data-driven source chips, and the day-grouped feed. It is re-rendered
// as a fragment (#scans-list) on every filter change.
type TenantScansView struct {
	SourceOptions []ScanSourceOption
	Days          []ScanDayGroupView
	ScanCount     int
	DomainCount   int
	ChangeCount   int
	CleanCount    int
}

// ScanSourceOption is one source chip, data-driven from the faceted SourceCounts.
type ScanSourceOption struct {
	Value string // user_supplied | discovered (filter value)
	Class string // user | disc (CSS dot/badge class)
	Label string // User | Discovered
	Count int
}

// ScanDayGroupView is one day divider plus the scan rows under it.
type ScanDayGroupView struct {
	Label string // Today | Yesterday | weekday
	Date  string // dimmed date, e.g. "09 Jun"
	Scans []ScanRowView
}

// ScanRowView is one scan run: a collapsed line plus an inline-expanding diff.
// All time/diff text is precomputed by the handler so the template stays dumb.
type ScanRowView struct {
	ScanUID       string
	DomainUID     string
	Label         string // bold leading label
	ApexSuffix    string // dimmed apex suffix, empty for an apex
	SourceClass   string // user | disc
	SourceLabel   string // user | discovered
	State         string // changed | clean | baseline (node-dot + summary cell)
	AbsoluteTime  string // "14:38"
	RelativeTime  string // "4m ago"
	ParentScanUID string
	ParentURL     string // timeline deep-link to the parent scan (empty for baseline)
	DeltaHead     string // "3 changes since scan_x" / "baseline — 14 records first observed"
	DeltaMeta     string // "scan_x · 2026-06-09 14:38:02 UTC[ · no parent]"
	CleanMessage  string // clean-state body text
	TimelineURL   string
	Segments      []ScanSegment
	Pills         []ScanPill
	Changes       []ScanChangeView
	IsBaseline    bool
}

// ScanSegment is one proportional slice of a scan row's change seg-bar.
type ScanSegment struct {
	Class string // c | u | d
	Width string // e.g. "34%"
}

// ScanPill is one per-change-kind count chip on a scan row.
type ScanPill struct {
	Class string // c | u | d
	Glyph string // + | ~ | −
	Count int
}

// ScanChangeView is one entity-type diff row in the expanded detail grid.
type ScanChangeView struct {
	Class      string // c | u | d
	Op         string // + | ~ | −
	EntityType string
	CountLabel string // "1 created"
}

// scanOpen returns the datastar expression that flips a scan's membership in the
// $open array (inline expand, zero round-trip).
func scanOpen(uid string) string {
	return fmt.Sprintf(
		"$open = $open.includes('%s') ? $open.filter(k => k !== '%s') : [...$open, '%s']",
		uid, uid, uid,
	)
}

// scanOpenClass toggles the 'open' class on a scan row when it is expanded.
func scanOpenClass(uid string) string {
	return fmt.Sprintf("{'open': $open.includes('%s')}", uid)
}

// srcToggle single-selects a source: clicking the active chip clears it, then
// re-fetches so the server applies the new filter.
func srcToggle(src string) string {
	return fmt.Sprintf("$src = $src === '%s' ? '' : '%s'; @get('/app/scans')", src, src)
}

// srcChipClass marks a source chip active when it is the selected source.
func srcChipClass(src string) string { return fmt.Sprintf("{'on': $src === '%s'}", src) }

// detailSignals builds the domain-detail signal object, defaulting the open tab
// to InitialTab. When the page is deep-linked to the Timeline tab, tlLoaded starts
// true so the timeline content loads once via intersect and the tab-click handler
// does not re-fetch it (which would drop the deep-link's scan highlight).
func detailSignals(initialTab string) string {
	tlLoaded := "false"
	if initialTab == "timeline" {
		tlLoaded = "true"
	}
	return fmt.Sprintf(`{"tab":"%s","tlLoaded":%s,"fnLoaded":false}`, initialTab, tlLoaded)
}

// timelineFullLoad returns the datastar @get that loads the full Timeline tab,
// carrying the deep-link scan uid so the targeted scan renders highlighted.
func timelineFullLoad(uid, scan string) string {
	url := "/app/domains/" + uid + "/timeline/full"
	if scan != "" {
		url += "?scan=" + scan
	}
	return fmt.Sprintf("@get('%s')", url)
}

// ComingSoonProps holds data for the coming-soon placeholder page.
type ComingSoonProps struct {
	Glyph string
	Title string
	Blurb string
	Shell AppShellProps
}

// ContentErrorProps holds data for the reusable error fragment.
type ContentErrorProps struct {
	Message  string
	RetryURL string
}

// ToastView is the presentation model for a single toast notification.
// Variant is one of ok|crit|warn|info and drives both the colour class and the
// icon. ID must be unique per toast so idiomorph appends each one onto the stack
// rather than morphing them together.
type ToastView struct {
	ID        string
	Variant   string
	Tag       string
	Title     string
	Desc      string
	Timestamp string
}

// toastIcon maps a toast variant to its glyph. Mirrors the variant→icon mapping
// the action handlers rely on, kept in the template so callers only pick a variant.
func toastIcon(variant string) string {
	switch variant {
	case "crit":
		return "⚠"
	case "warn":
		return "!"
	case "info":
		return "⟳"
	default:
		return "✓"
	}
}
