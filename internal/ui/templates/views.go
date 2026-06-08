package templates

import "fmt"

// postWithCSRF returns a datastar data-on-click action string that POSTs to url
// carrying the CSRF token in the X-CSRF-Token header.
// Pattern used on every state-mutating datastar action.
func postWithCSRF(url, token string) string {
	return fmt.Sprintf("@post('%s', {headers: {'X-CSRF-Token': '%s'}})", url, token)
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
		apex, apex, apex,
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
	Apex             string
	Header           DomainRowView
	HasOwn           bool
	Children         []DomainRowView
	SubCount         int
	RollupSeverity   string   // worst severity across header+children
	Rollup           []string // distinct severities present, worst-first
	FindingsSeverity string   // apex badge CSS class (crit|warn|ok|info)
	FindingsLabel    string   // apex badge text, e.g. "1 critical" / "clean"
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
	Shell            AppShellProps
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

// ScanGroupView groups one scan's changes in the full Timeline tab.
type ScanGroupView struct {
	ScanID      string
	When        string
	Meta        string
	Changes     []ChangeView
	ChangeCount int
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
