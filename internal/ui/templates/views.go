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
	Shell   AppShellProps
	Stats   DomainsStats
	Domains []DomainRowView
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
	UID           string
	Name          string
	Severity      string
	RecordCount   string
	FindingsCount string
	Type          string
	Source        string
	Added         string
	Scanned       string
	Shell         AppShellProps
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
