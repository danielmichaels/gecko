package templates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/danielmichaels/gecko/assets"
)

// staticURL appends a short content hash to an embedded static asset path so a
// changed asset busts the browser cache (the file server ignores the query
// string). The hash is derived from the go:embed bytes — fixed at build time —
// so it is computed once per path and cached. A missing asset is returned
// unchanged rather than failing the render.
var (
	staticVerMu sync.Mutex
	staticVers  = map[string]string{}
)

func staticURL(path string) string {
	staticVerMu.Lock()
	v, ok := staticVers[path]
	if !ok {
		if b, err := assets.EmbeddedAssets.ReadFile(strings.TrimPrefix(path, "/")); err == nil {
			sum := sha256.Sum256(b)
			v = hex.EncodeToString(sum[:])[:10]
		}
		staticVers[path] = v
	}
	staticVerMu.Unlock()
	if v == "" {
		return path
	}
	return path + "?v=" + v
}

// postWithCSRF returns a datastar data-on-click action string that POSTs to url
// carrying the CSRF token in the X-CSRF-Token header.
// Pattern used on every state-mutating datastar action.
func postWithCSRF(url, token string) string {
	return fmt.Sprintf("@post('%s', {headers: {'X-CSRF-Token': '%s'}})", url, token)
}

// logoutAction returns the data-on:click expression for the user-menu logout item:
// confirm, then POST to /app/logout with the CSRF token. The handler revokes the
// session, clears the cookie, and SSE-redirects to the login page.
func logoutAction(token string) string {
	return "if(!confirm('Log out of gecko?')) return; " + postWithCSRF("/app/logout", token)
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

// attachSignals returns the signals string carrying just the invite token for the
// one-click "attach to an existing account" accept action.
func attachSignals(token string) string {
	return fmt.Sprintf(`{"token":"%s"}`, token)
}

// switchTenantAction returns the data-on:click action that POSTs a tenant switch.
// The tenant uid is server-generated (tenant_xxxx), but it is JSON-encoded for the
// query string as defence-in-depth.
func switchTenantAction(uid, token string) string {
	uidJSON, _ := json.Marshal(uid)
	tokenJSON, _ := json.Marshal(token)
	return fmt.Sprintf(
		"@post('/app/switch-tenant?tenant='+encodeURIComponent(%s), {headers: {'X-CSRF-Token': %s}})",
		uidJSON,
		tokenJSON,
	)
}

// createWorkspaceAction prompts for a workspace name and POSTs it to create a new
// tenant, then the handler switches the session to it. The name is stashed in the
// wsName signal so it travels in the request body.
func createWorkspaceAction(token string) string {
	tokenJSON, _ := json.Marshal(token)
	return fmt.Sprintf(
		"const n=prompt('Name your new workspace'); if(!n){return}; $wsName=n; @post('/app/workspaces', {headers: {'X-CSRF-Token': %s}})",
		tokenJSON,
	)
}

// resetSignals returns a JSON signals string for the reset-password form, with the
// token pre-populated so it travels in the POST body.
func resetSignals(token string) string {
	return fmt.Sprintf(`{"token":"%s","newPassword":""}`, token)
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
	// Tenants lists every workspace the caller belongs to, driving the topbar tenant
	// switcher. When the caller belongs to a single tenant the chip renders static.
	Tenants    []TenantOption
	ResolverOK bool
	// CanManageDomains gates the owner/manager-only domain controls (add, rescan,
	// delete). It mirrors the service-layer guard so the UI hides what the API would
	// reject; the 403 remains the authoritative backstop.
	CanManageDomains bool
}

// TenantOption is one workspace in the topbar tenant switcher. Active marks the
// caller's current active tenant; UID feeds the switch endpoint.
type TenantOption struct {
	UID    string
	Name   string
	Role   string
	Active bool
}

// LoginPageProps holds data for the login page.
type LoginPageProps struct {
	CSRFToken string
	Error     string
	// ShowSignup gates the "create an account" link; mirrors SIGNUP_ENABLED.
	ShowSignup bool
}

// SignupPageProps holds data for the self-service signup page.
type SignupPageProps struct {
	Error string
}

// ForgotPasswordPageProps holds data for the request-password-reset page.
type ForgotPasswordPageProps struct {
	SuccessMsg string
	Error      string
}

// ResetPasswordPageProps holds data for the set-new-password page.
type ResetPasswordPageProps struct {
	Token string
	Error string
}

// AcceptInvitePageProps holds data for the accept-invitation page. Mode selects
// the acceptance flow: "new" sets a password for a brand-new account; "attach"
// shows a one-click accept for an already-logged-in matching account; "login"
// tells an existing account to sign in first (a link alone never attaches a tenant
// to someone else's identity).
type AcceptInvitePageProps struct {
	CSRFToken    string
	Token        string
	TenantName   string
	InviterEmail string
	Role         string
	InviteeEmail string
	Expiry       string
	Error        string
	Mode         string
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
	Stats      DomainsStats
	Layout     string
	Domains    []DomainRowView
	Groups     []DomainGroupView
	TLDOptions []string
	Shell      AppShellProps
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
	// Status is the raw domain status (active|inactive|pending). The paused badge
	// and the Pause/Resume toggle are driven by it directly, not by Severity —
	// severityForStatus collapses inactive into "ok", which would hide the pause.
	Status string
	// ScanFrequency is the domain's per-domain cadence override ("" = inheriting
	// the tenant default). ScanFrequency maps to a store.ScanFrequency preset.
	ScanFrequency string
	// ScanFrequencyLabel is the human label for ScanFrequency, shown in the
	// read-only (viewer) branch so it reads "Weekly" rather than "weekly".
	ScanFrequencyLabel string
	// NextScan is the humanised time until the next scheduled scan ("in 3h",
	// "due", "—"). Computed by nextScanLabel.
	NextScan string
	// EffectiveDefaultLabel is the human label for the tenant default cadence,
	// rendered in the "Use default (X)" select option.
	EffectiveDefaultLabel string
	Shell                 AppShellProps
	// DeleteImpactCount is the number of domains a delete would cascade away (self
	// plus discovered children), surfaced in the delete confirmation.
	DeleteImpactCount int
	// CanManage gates the scan-frequency editable select and save button,
	// mirroring service.OwnerOrManager; the service enforces the actual guard.
	CanManage bool
}

// DomainLifecycleProps is the slice of detail-page data the lifecycle controls
// (primary action + overflow menu) need. It is rendered both inline on first load
// and re-patched over SSE after a status flip, so it lives as a standalone fragment.
type DomainLifecycleProps struct {
	UID       string
	Name      string
	Status    string
	CSRFToken string
	// Scan cadence now lives inside the overflow menu, so the fragment carries the
	// same cadence data the standalone panel used to.
	ScanFrequency         string
	ScanFrequencyLabel    string
	EffectiveDefaultLabel string
	DeleteImpactCount     int
	CanManage             bool
}

// Lifecycle projects the detail props onto the lifecycle-controls fragment.
func (p DomainDetailPageProps) Lifecycle() DomainLifecycleProps {
	return DomainLifecycleProps{
		UID:                   p.UID,
		Name:                  p.Name,
		Status:                p.Status,
		CSRFToken:             p.Shell.CSRFToken,
		DeleteImpactCount:     p.DeleteImpactCount,
		ScanFrequency:         p.ScanFrequency,
		ScanFrequencyLabel:    p.ScanFrequencyLabel,
		EffectiveDefaultLabel: p.EffectiveDefaultLabel,
		CanManage:             p.CanManage,
	}
}

// RecordRowView is the presentation model for one DNS record row.
type RecordRowView struct {
	Type  string
	Value string
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
	SevCounts    map[string]int // tier (crit|high|med|low) -> faceted chip count
	Groups       []FindingGroupView
	KindOptions  []FindingKindOption
	OpenCount    int
	DomainCount  int
	CritCount    int
	HighCount    int
	MedCount     int
	ShowSilenced bool   // reflects the "show silenced" toggle state
	CanManage    bool   // owner/manager: show silence/acknowledge controls
	CSRFToken    string // per-session token for the mutation actions
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
	IssueType   string // stable check code, for the silence action
	Icon        string
	Title       string
	Description string
	Evidence    string
	FixHint     string
	FirstSeen   string
	Suppressed  bool   // rendered dimmed with a "silenced" pill
	CanManage   bool   // owner/manager: show silence/acknowledge controls
	CSRFToken   string // per-session token for the mutation actions
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

// csrfHeader returns the datastar options object carrying the per-session CSRF
// token, required on every browser-initiated mutation.
func csrfHeader(token string) string {
	return fmt.Sprintf("{headers: {'X-CSRF-Token': '%s'}}", token)
}

// silenceTenantAction posts a tenant-global silence rule for a check, then
// re-fetches the findings list so the now-suppressed row drops out.
func silenceTenantAction(kind, issueType, token string) string {
	return fmt.Sprintf(
		"@post('/app/findings/silence?scope=tenant&kind=%s&issue_type=%s', %s)",
		kind, issueType, csrfHeader(token),
	)
}

// silenceDomainAction posts a per-domain silence rule for a check.
func silenceDomainAction(kind, issueType, domainUID, token string) string {
	return fmt.Sprintf(
		"@post('/app/findings/silence?scope=domain&kind=%s&issue_type=%s&domain_uid=%s', %s)",
		kind, issueType, domainUID, csrfHeader(token),
	)
}

// acknowledgeAction posts an acknowledgement for one finding instance by uid.
func acknowledgeAction(uid, token string) string {
	return fmt.Sprintf("@post('/app/findings/%s/acknowledge', %s)", uid, csrfHeader(token))
}

// removeSuppressionAction deletes a silence rule or ack by uid from the settings list.
func removeSuppressionAction(uid, token string) string {
	return fmt.Sprintf("@delete('/app/suppressions/%s', %s)", uid, csrfHeader(token))
}

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
// scanFrequency is pre-filled with the domain's current override (empty string
// means inherit the tenant default).
func detailSignals(initialTab, scanFrequency string) string {
	tlLoaded := "false"
	if initialTab == "timeline" {
		tlLoaded = "true"
	}
	return fmt.Sprintf(
		`{"tab":"%s","tlLoaded":%s,"fnLoaded":false,"lcMenu":false,"scanFrequency":"%s"}`,
		initialTab,
		tlLoaded,
		scanFrequency,
	)
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

// SettingsPageProps holds data for the settings page. CanManage gates the
// owner/manager-only API-key controls (create, revoke) and the scan-frequency
// control, mirroring the service-layer guard; the 403 stays the authoritative
// backstop. DefaultScanFrequency is the tenant's current default cadence preset.
type SettingsPageProps struct {
	DefaultScanFrequency   string
	LastDigestSent         string
	LastAlertSent          string
	APIKeys                []APIKeyRowView
	SilencedChecks         []SuppressionRowView
	Shell                  AppShellProps
	CanManage              bool
	NotifyDailyDigest      bool
	NotifyHighImpact       bool
	NotifyHighImpactAlerts bool
	NotifyOptOut           bool
}

// SuppressionRowView is the presentation model for one silence rule or ack in the
// settings "Silenced checks" list.
type SuppressionRowView struct {
	UID       string
	Scope     string // tenant | domain | finding
	ScopeText string // human label, e.g. "All domains" / domain name / "Finding"
	State     string // silenced | acknowledged | resolved
	Label     string // the check title (or finding uid for acks)
	Reason    string
	CreatedBy string
	Created   string
	Expires   string // "" = never
}

// APIKeyRowView is the presentation model for one API key in the settings list.
// Secrets are never present here — only the prefix and lifecycle timestamps. A
// revoked key is rendered inert (no revoke control).
type APIKeyRowView struct {
	UID      string
	Name     string
	Prefix   string
	Created  string
	LastUsed string
	Expires  string
	Revoked  bool
}

// APIKeySecretView carries a freshly minted key's plaintext for the one-time
// reveal. It is rendered into #apikey-secret once, on creation, and never again.
type APIKeySecretView struct {
	Name string
	Raw  string
}

// TeamPageProps holds data for the team-management page. CanManage gates the
// owner/manager-only controls (invite, change role, remove, revoke), mirroring
// the service-layer guard; the 403 remains the authoritative backstop. ActorRole
// is the caller's role, used to cap the grantable-role options.
type TeamPageProps struct {
	ActorRole string
	Members   []MemberRowView
	Invites   []InviteRowView
	Shell     AppShellProps
	Stats     TeamStats
	CanManage bool
}

// TeamStats holds the four stat-strip counts for the team page.
type TeamStats struct {
	Members  int
	Owners   int
	Managers int
	Pending  int
}

// MemberRowView is the presentation model for one team member. Manageable is true
// when the caller outranks-or-equals this member (service.requireCanManage); only
// then are the role select and remove control rendered.
type MemberRowView struct {
	UID         string
	Email       string
	Name        string
	Initials    string
	Role        string
	Status      string
	StatusClass string
	Joined      string
	Manageable  bool
}

// InviteRowView is the presentation model for one pending invitation. Expired is
// true once the invite is past its expiry; it renders dimmed with an "expired"
// badge but can still be revoked to clear the row.
type InviteRowView struct {
	UID       string
	Email     string
	Role      string
	InvitedBy string
	Expires   string
	Expired   bool
}

// InviteLinkView carries a freshly created invitation's one-time accept URL for
// the reveal panel. With no mailer wired, this link is the only delivery channel,
// and the plaintext token exists only on the create response — rendered into
// #team-invite-secret once and never reproducible.
type InviteLinkView struct {
	Email string
	URL   string
}

// roleRank mirrors service/authz.go's privilege ordering for UI gating only. The
// service stays the authoritative guard; this just decides which controls and
// options to render. superadmin outranks owner but is never offered as grantable.
var roleRank = map[string]int{"viewer": 1, "manager": 2, "owner": 3, "superadmin": 4}

// grantableRoles returns the roles the actor may assign — every role at or below
// their own rank, excluding superadmin. Mirrors service.requireCanGrant so the UI
// never offers an option the API would reject with a 403.
func grantableRoles(actorRole string) []string {
	out := make([]string, 0, 3)
	for _, r := range []string{"viewer", "manager", "owner"} {
		if roleRank[r] <= roleRank[actorRole] {
			out = append(out, r)
		}
	}
	return out
}

// roleBadgeClass maps a role to its badge accent class. viewer renders neutral.
func roleBadgeClass(role string) string {
	switch role {
	case "owner":
		return "role-owner"
	case "manager":
		return "info"
	default:
		return ""
	}
}

// changeMemberRole returns the data-on:change action that PUTs the newly selected
// role for a member. uid and token are JSON-encoded into JS string literals (HTML
// escaping alone does not protect a JS-attribute context — the DOM reverses it
// before datastar evaluates), and the chosen role is read live from el.value.
func changeMemberRole(uid, token string) string {
	uidJSON, _ := json.Marshal(uid)
	tokenJSON, _ := json.Marshal(token)
	return fmt.Sprintf(
		"@put('/app/team/members/'+%s+'?role='+encodeURIComponent(el.value), {headers: {'X-CSRF-Token': %s}})",
		uidJSON,
		tokenJSON,
	)
}

// removeMember returns the confirm-then-DELETE action for removing a member. Every
// interpolated value (uid, email, token) is JSON-encoded into a JS string literal
// so a crafted email cannot break out of the expression.
func removeMember(uid, email, token string) string {
	uidJSON, _ := json.Marshal(uid)
	emailJSON, _ := json.Marshal(email)
	tokenJSON, _ := json.Marshal(token)
	return fmt.Sprintf(
		"if(!confirm('Remove '+%s+' from the team?')) return; @delete('/app/team/members/'+%s, {headers: {'X-CSRF-Token': %s}})",
		emailJSON,
		uidJSON,
		tokenJSON,
	)
}

// revokeInvite returns the confirm-then-DELETE action for revoking a pending
// invitation, JSON-encoding every interpolated value as a JS string literal.
func revokeInvite(uid, email, token string) string {
	uidJSON, _ := json.Marshal(uid)
	emailJSON, _ := json.Marshal(email)
	tokenJSON, _ := json.Marshal(token)
	return fmt.Sprintf(
		"if(!confirm('Revoke the invitation for '+%s+'?')) return; @delete('/app/team/invitations/'+%s, {headers: {'X-CSRF-Token': %s}})",
		emailJSON,
		uidJSON,
		tokenJSON,
	)
}

// statusToggleAction returns the data-on:click action that POSTs the opposite of
// the current status to the lifecycle endpoint. uid and token are JSON-encoded
// into JS string literals (the next status is a fixed enum keyword, never
// user-supplied, so it is safe to inline into the query string).
func statusToggleAction(uid, currentStatus, token string) string {
	next := "inactive"
	if currentStatus == "inactive" {
		next = "active"
	}
	uidJSON, _ := json.Marshal(uid)
	tokenJSON, _ := json.Marshal(token)
	return fmt.Sprintf(
		"@post('/app/domains/'+%s+'/status?status=%s', {headers: {'X-CSRF-Token': %s}})",
		uidJSON, next, tokenJSON,
	)
}

// deleteDomainWithConfirm returns the confirm-then-DELETE action for the detail
// page. The cascade count makes the prompt honest about how much a delete removes;
// ?redirect=/app/domains tells the handler to navigate away rather than remove a
// row. Every user-supplied value (uid, name, token) is JSON-encoded into a JS
// string literal so a crafted domain name cannot break out of the expression.
func deleteDomainWithConfirm(uid, name string, count int, token string) string {
	uidJSON, _ := json.Marshal(uid)
	nameJSON, _ := json.Marshal(name)
	tokenJSON, _ := json.Marshal(token)
	prefix, _ := json.Marshal("Delete ")
	suffix := "? This permanently removes all its records and findings and cannot be undone."
	if count > 1 {
		suffix = fmt.Sprintf(
			" and %d related domain(s)? This permanently removes them plus all records and findings, and cannot be undone.",
			count-1,
		)
	}
	suffixJSON, _ := json.Marshal(suffix)
	return fmt.Sprintf(
		"if(!confirm(%s+%s+%s)) return; @delete('/app/domains/'+%s+'?redirect=/app/domains', {headers: {'X-CSRF-Token': %s}})",
		prefix,
		nameJSON,
		suffixJSON,
		uidJSON,
		tokenJSON,
	)
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
