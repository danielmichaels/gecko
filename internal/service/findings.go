package service

import (
	"context"
	"sort"
	"strings"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// FindingsService exposes read access to a domain's security findings.
type FindingsService struct {
	*Service
}

// FindingView is a presentation-ready security finding for one card.
type FindingView struct {
	Kind        string // SPF | DKIM | DMARC | ZoneTransfer | ZONE
	Severity    string // critical | high | medium | low | info
	SevClass    string // crit | warn | info | ok — 2-tier (per-domain card)
	Tier        string // crit | high | med | low | ok — 4-tier (tenant screen)
	Icon        string // glyph for the card icon
	Title       string
	Description string
	Evidence    string
	FixHint     string
	// Tenant-wide fields; zero for the per-domain card and ignored by its renderer.
	DomainUID  string
	DomainName string
	FindingUID string
	FirstSeen  string // "2006-01-02"
}

// FindingsResult is a domain's findings sorted worst-first, with count buckets
// for the summary strip (info/compliant collapse into "healthy").
type FindingsResult struct {
	Findings      []FindingView
	TotalCount    int
	CriticalCount int
	WarningCount  int
	HealthyCount  int
}

// FindingsListOptions narrows a tenant-wide findings listing. Empty strings mean
// "no filter". Severity is a single 4-tier value (crit|high|med|low) to match the
// single-select UI; Kind is SPF|DKIM|DMARC|ZONE; DomainQuery is a case-insensitive
// substring match on the domain name.
type FindingsListOptions struct {
	Severity         string
	Kind             string
	DomainQuery      string
	IncludeCompliant bool
}

// TenantFindingsResult is the tenant-wide roll-up: findings grouped by domain
// (worst-first), the totals strip, and per-facet counts for the filter bar.
// KindCounts and SeverityCounts are faceted — each ignores its own filter so the
// type dropdown and severity chips stay populated as the user narrows.
type TenantFindingsResult struct {
	KindCounts     map[string]int
	SeverityCounts map[string]int
	Groups         []DomainFindingGroup
	Totals         FindingTotals
}

// DomainFindingGroup is one domain's findings plus its per-tier rollup counts.
type DomainFindingGroup struct {
	DomainUID  string
	DomainName string
	Findings   []FindingView
	CritCount  int
	HighCount  int
	WarnCount  int // medium tier
	LowCount   int
}

// FindingTotals drives the stat strip; counts reflect the fully-filtered view.
type FindingTotals struct {
	Open        int
	Critical    int
	High        int
	Medium      int
	Low         int
	DomainCount int
}

// FlatFindingsResult is the API-facing tenant-wide listing: a flat, paginated
// slice of findings (each carrying its domain identity) plus the unpaginated
// total for pagination metadata.
type FlatFindingsResult struct {
	Findings   []FindingView
	TotalCount int64
}

// ListByDomain aggregates the implemented finding types (SPF, DKIM, DMARC, zone
// transfer, certificate, dnssec) for a domain into a single severity-sorted
// list. Returns
// ErrNotFound when the domain is not in the caller's tenant.
func (s *FindingsService) ListByDomain(
	ctx context.Context,
	p *auth.Principal,
	domainUID string,
) (FindingsResult, error) {
	if _, err := s.DB.DomainsGetByID(ctx, store.DomainsGetByIDParams{
		Uid:      domainUID,
		TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
	}); err != nil {
		return FindingsResult{}, ErrNotFound
	}

	var findings []FindingView

	tenantID := pgtype.Int4{Int32: p.TenantID, Valid: true}
	if spf, err := s.DB.AssessGetSPFFindingByDomainID(ctx, store.AssessGetSPFFindingByDomainIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range spf {
			findings = append(findings, mapEmailFinding(
				"SPF", f.Severity, f.Status, f.IssueType, f.Details, f.SpfValue,
			))
		}
	}
	if dkim, err := s.DB.AssessDKIMFindingsByDomainID(ctx, store.AssessDKIMFindingsByDomainIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range dkim {
			findings = append(findings, mapEmailFinding(
				"DKIM", f.Severity, f.Status, f.IssueType, f.Details, f.DkimValue,
			))
		}
	}
	if dmarc, err := s.DB.AssessGetDMARCFindingsByDomainID(ctx, store.AssessGetDMARCFindingsByDomainIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range dmarc {
			findings = append(findings, mapEmailFinding(
				"DMARC", f.Severity, f.Status, f.IssueType, f.Details, f.DmarcValue,
			))
		}
	}
	if zones, err := s.DB.AssessGetZoneTransferFindingsByDomainUID(ctx, store.AssessGetZoneTransferFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range zones {
			findings = append(findings, mapZoneTransferFinding(f))
		}
	}
	if certs, err := s.DB.AssessGetCertificateFindingsByDomainUID(ctx, store.AssessGetCertificateFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range certs {
			findings = append(findings, mapStandardFinding(
				"CERT", f.Severity, f.Status, f.IssueType, f.Details,
			))
		}
	}
	if dnssec, err := s.DB.AssessGetDNSSECFindingsByDomainUID(ctx, store.AssessGetDNSSECFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range dnssec {
			findings = append(findings, mapStandardFinding(
				"DNSSEC", f.Severity, f.Status, f.IssueType, f.Details,
			))
		}
	}
	if caaConfig, err := s.DB.AssessGetCAAConfigurationFindingsByDomainUID(ctx, store.AssessGetCAAConfigurationFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range caaConfig {
			findings = append(findings, mapStandardFinding(
				"CAA_CONFIG", f.Severity, f.Status, f.IssueType, f.Details,
			))
		}
	}
	if caaCompliance, err := s.DB.AssessGetCAAComplianceFindingsByDomainUID(ctx, store.AssessGetCAAComplianceFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range caaCompliance {
			findings = append(findings, mapStandardFinding(
				"CAA_COMPLIANCE", f.Severity, f.Status, f.IssueType, f.Details,
			))
		}
	}
	if minRecords, err := s.DB.AssessGetMinimumRecordSetFindingsByDomainUID(ctx, store.AssessGetMinimumRecordSetFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range minRecords {
			findings = append(findings, mapStandardFinding(
				"MIN_RECORDS", f.Severity, f.Status, f.IssueType, f.Details,
			))
		}
	}
	if emailCompliance, err := s.DB.AssessGetEmailAuthComplianceFindingsByDomainUID(ctx, store.AssessGetEmailAuthComplianceFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range emailCompliance {
			findings = append(findings, mapStandardFinding(
				"EMAIL_COMPLIANCE", f.Severity, f.Status, f.IssueType, f.Details,
			))
		}
	}
	if nsConfig, err := s.DB.AssessGetNSConfigurationFindingsByDomainUID(ctx, store.AssessGetNSConfigurationFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range nsConfig {
			findings = append(findings, mapStandardFinding(
				"NS_CONFIG", f.Severity, f.Status, f.IssueType, f.Details,
			))
		}
	}
	if nsRedundancy, err := s.DB.AssessGetNameserverRedundancyFindingsByDomainUID(ctx, store.AssessGetNameserverRedundancyFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range nsRedundancy {
			findings = append(findings, mapStandardFinding(
				"NS_REDUNDANCY", f.Severity, f.Status, f.IssueType, f.Details,
			))
		}
	}
	if nsReach, err := s.DB.AssessGetNameserverReachabilityFindingsByDomainUID(ctx, store.AssessGetNameserverReachabilityFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range nsReach {
			findings = append(findings, mapStandardFinding(
				"NS_REACHABILITY", f.Severity, f.Status, f.IssueType, f.Details,
			))
		}
	}
	if nsLatency, err := s.DB.AssessGetDNSResolutionLatencyFindingsByDomainUID(ctx, store.AssessGetDNSResolutionLatencyFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range nsLatency {
			findings = append(findings, mapStandardFinding(
				"NS_LATENCY", f.Severity, f.Status, "high_latency", f.Details,
			))
		}
	}
	if nsConsistency, err := s.DB.AssessGetDNSResolutionConsistencyFindingsByDomainUID(ctx, store.AssessGetDNSResolutionConsistencyFindingsByDomainUIDParams{
		Uid:      domainUID,
		TenantID: tenantID,
	}); err == nil {
		for _, f := range nsConsistency {
			findings = append(findings, mapStandardFinding(
				"NS_CONSISTENCY", f.Severity, f.Status, "resolver_mismatch", f.Details,
			))
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})

	res := FindingsResult{Findings: findings, TotalCount: len(findings)}
	for _, f := range findings {
		switch f.SevClass {
		case "crit":
			res.CriticalCount++
		case "warn":
			res.WarningCount++
		default: // info + ok both read as "healthy" in the summary strip
			res.HealthyCount++
		}
	}
	return res, nil
}

// ListByTenant rolls up every finding across the caller's domains into a
// grouped, filtered, worst-first view. Tenant isolation is enforced by the SQL
// join-gate in FindingsListByTenant — never by a Go-side tenant filter.
func (s *FindingsService) ListByTenant(
	ctx context.Context,
	p *auth.Principal,
	opts FindingsListOptions,
) (TenantFindingsResult, error) {
	rows, err := s.DB.FindingsListByTenant(ctx, store.FindingsListByTenantParams{
		TenantID:         pgtype.Int4{Int32: p.TenantID, Valid: true},
		IncludeCompliant: opts.IncludeCompliant,
	})
	if err != nil {
		return TenantFindingsResult{}, err
	}
	return buildTenantFindings(rows, opts), nil
}

// ListByTenantFlat returns the tenant-wide findings as a flat, worst-first,
// paginated slice for the REST API. It reuses ListByTenant's tenant-gated SQL,
// filtering and worst-first ordering, then flattens the per-domain groups.
//
// FLAG: FindingsListByTenant is a 4-way UNION ALL scoped to the tenant; finding
// counts per tenant are bounded (assessors write ~1 row per check per domain), so
// pagination here is an in-memory slice. For tenants with O(10k+) domains this
// should move to SQL-level LIMIT/OFFSET.
func (s *FindingsService) ListByTenantFlat(
	ctx context.Context,
	p *auth.Principal,
	opts FindingsListOptions,
	pageSize, offset int32,
) (FlatFindingsResult, error) {
	grouped, err := s.ListByTenant(ctx, p, opts)
	if err != nil {
		return FlatFindingsResult{}, err
	}

	var all []FindingView
	for _, g := range grouped.Groups {
		all = append(all, g.Findings...)
	}

	total := int64(len(all))
	lo := int(offset)
	if lo > len(all) {
		lo = len(all)
	}
	hi := lo + int(pageSize)
	if hi > len(all) {
		hi = len(all)
	}
	return FlatFindingsResult{Findings: all[lo:hi], TotalCount: total}, nil
}

// buildTenantFindings is the pure grouping/filter/sort/count layer over the raw
// UNION rows (which arrive pre-sorted domain-then-severity). Separated from the
// DB call so it is exhaustively unit-testable with synthetic rows.
func buildTenantFindings(
	rows []store.FindingsListByTenantRow,
	opts FindingsListOptions,
) TenantFindingsResult {
	res := TenantFindingsResult{
		KindCounts:     map[string]int{},
		SeverityCounts: map[string]int{},
	}
	query := strings.ToLower(strings.TrimSpace(opts.DomainQuery))
	groupIndex := make(map[string]int, len(rows))

	for _, row := range rows {
		f := mapTenantRow(row)

		if query != "" && !strings.Contains(strings.ToLower(f.DomainName), query) {
			continue
		}
		matchSev := opts.Severity == "" || f.Tier == opts.Severity
		matchKind := opts.Kind == "" || f.Kind == opts.Kind

		// Faceted counts: each control ignores its own filter so it stays
		// populated as the user narrows the others.
		if matchSev {
			res.KindCounts[f.Kind]++
		}
		if matchKind {
			res.SeverityCounts[f.Tier]++
		}
		if !matchSev || !matchKind {
			continue
		}

		gi, ok := groupIndex[f.DomainUID]
		if !ok {
			gi = len(res.Groups)
			groupIndex[f.DomainUID] = gi
			res.Groups = append(res.Groups, DomainFindingGroup{
				DomainUID:  f.DomainUID,
				DomainName: f.DomainName,
			})
		}
		g := &res.Groups[gi]
		g.Findings = append(g.Findings, f)
		switch f.Tier {
		case "crit":
			g.CritCount++
			res.Totals.Critical++
		case "high":
			g.HighCount++
			res.Totals.High++
		case "med":
			g.WarnCount++
			res.Totals.Medium++
		case "low":
			g.LowCount++
			res.Totals.Low++
		}
		res.Totals.Open++
	}
	res.Totals.DomainCount = len(res.Groups)

	sort.SliceStable(res.Groups, func(i, j int) bool {
		ri, rj := groupWorstRank(res.Groups[i]), groupWorstRank(res.Groups[j])
		if ri != rj {
			return ri < rj
		}
		if li, lj := len(res.Groups[i].Findings), len(res.Groups[j].Findings); li != lj {
			return li > lj
		}
		return res.Groups[i].DomainName < res.Groups[j].DomainName
	})
	return res
}

// groupWorstRank ranks a group by its most severe tier (lower is worse) so the
// domain with the worst exposure sorts first.
func groupWorstRank(g DomainFindingGroup) int {
	switch {
	case g.CritCount > 0:
		return 0
	case g.HighCount > 0:
		return 1
	case g.WarnCount > 0:
		return 2
	case g.LowCount > 0:
		return 3
	default:
		return 4
	}
}

// mapTenantRow maps a UNION row to a FindingView, reusing the shared text and
// severity helpers. A refused zone transfer is healthy regardless of its stored
// severity (mirrors mapZoneTransferFinding).
func mapTenantRow(row store.FindingsListByTenantRow) FindingView {
	class := severityClass(row.Severity, row.Status)
	tier := severityTier(row.Severity)
	title, desc, fix := findingText(row.IssueType)
	if row.Details.Valid && row.Details.String != "" {
		desc = row.Details.String
	}
	if row.Kind == "ZONE" && row.IssueType == "zone_transfer_refused" {
		class, tier = "ok", "ok"
	}
	return FindingView{
		Kind:        row.Kind,
		Severity:    string(row.Severity),
		SevClass:    class,
		Tier:        tier,
		Icon:        severityIcon(class),
		Title:       title,
		Description: desc,
		Evidence:    row.Value.String,
		FixHint:     fix,
		DomainUID:   row.DomainUid,
		DomainName:  row.DomainName,
		FindingUID:  row.FindingUid,
		FirstSeen:   firstSeen(row.CreatedAt),
	}
}

// firstSeen renders a finding's creation timestamp as a plain date.
func firstSeen(ts pgtype.Timestamptz) string {
	if !ts.Valid {
		return ""
	}
	return ts.Time.Format("2006-01-02")
}

// mapEmailFinding maps an SPF/DKIM/DMARC finding row to a FindingView.
func mapEmailFinding(
	kind string,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType string,
	details, value pgtype.Text,
) FindingView {
	class := severityClass(severity, status)
	title, _, fix := findingText(issueType)
	return FindingView{
		Kind:        kind,
		Severity:    string(severity),
		SevClass:    class,
		Tier:        severityTier(severity),
		Icon:        severityIcon(class),
		Title:       title,
		Description: details.String,
		Evidence:    value.String,
		FixHint:     fix,
	}
}

// mapStandardFinding maps a finding row that carries no extra evidence column
// (certificate, dnssec) to a FindingView, preferring the stored details over the
// generic catalog description.
func mapStandardFinding(
	kind string,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType string,
	details pgtype.Text,
) FindingView {
	class := severityClass(severity, status)
	title, desc, fix := findingText(issueType)
	if details.Valid && details.String != "" {
		desc = details.String
	}
	return FindingView{
		Kind:        kind,
		Severity:    string(severity),
		SevClass:    class,
		Tier:        severityTier(severity),
		Icon:        severityIcon(class),
		Title:       title,
		Description: desc,
		FixHint:     fix,
	}
}

// mapZoneTransferFinding maps a zone-transfer finding. A refused transfer is
// healthy regardless of its stored severity; only an actually-possible AXFR is a
// real exposure.
func mapZoneTransferFinding(f store.ZoneTransferFindings) FindingView {
	class := severityClass(f.Severity, f.Status)
	issueType := zoneIssueType(f.ZoneTransferPossible)
	title, desc, fix := findingText(issueType)
	evidence := f.Nameserver + " — REFUSED"
	if f.ZoneTransferPossible {
		evidence = f.Nameserver + " — TRANSFERABLE"
	} else {
		class = "ok"
	}
	if f.Details.Valid && f.Details.String != "" {
		desc = f.Details.String
	}

	return FindingView{
		Kind:        "ZoneTransfer",
		Severity:    string(f.Severity),
		SevClass:    class,
		Tier:        severityTier(f.Severity),
		Icon:        severityIcon(class),
		Title:       title,
		Description: desc,
		Evidence:    evidence,
		FixHint:     fix,
	}
}

// findingText resolves presentation text for a finding from its issue type
// alone — pure and shared by the per-domain and tenant-wide mappers so the two
// cannot drift. Email findings carry their description in the row; zone-transfer
// descriptions are static (findingDescriptions).
func findingText(issueType string) (title, description, fixHint string) {
	return findingTitle(issueType), findingDescriptions[issueType], findingFixes[issueType]
}

// zoneIssueType maps a zone-transfer outcome to the synthetic issue type that
// keys its presentation text. Mirrors the CASE in FindingsListByTenant.
func zoneIssueType(possible bool) string {
	if possible {
		return "zone_transfer_exposed"
	}
	return "zone_transfer_refused"
}

// severityTier maps a finding severity to the 4-tier class used by the
// tenant-wide Findings screen (distinct from the 2-tier severityClass that the
// per-domain card uses). Info and anything unknown read as "ok".
func severityTier(s store.FindingSeverity) string {
	switch s {
	case store.FindingSeverityCritical:
		return "crit"
	case store.FindingSeverityHigh:
		return "high"
	case store.FindingSeverityMedium:
		return "med"
	case store.FindingSeverityLow:
		return "low"
	default:
		return "ok"
	}
}

// severityClass maps a finding's severity (and status, for the info tier) to a
// UI badge class. Open info findings stay "info"; compliant/closed ones go "ok".
func severityClass(s store.FindingSeverity, status store.FindingStatus) string {
	switch s {
	case store.FindingSeverityCritical, store.FindingSeverityHigh:
		return "crit"
	case store.FindingSeverityMedium, store.FindingSeverityLow:
		return "warn"
	default:
		if status == store.FindingStatusOpen {
			return "info"
		}
		return "ok"
	}
}

func severityIcon(class string) string {
	switch class {
	case "crit":
		return "!"
	case "warn":
		return "▲"
	case "info":
		return "ℹ"
	default:
		return "✓"
	}
}

func severityRank(severity string) int {
	switch store.FindingSeverity(severity) {
	case store.FindingSeverityCritical:
		return 1
	case store.FindingSeverityHigh:
		return 2
	case store.FindingSeverityMedium:
		return 3
	case store.FindingSeverityLow:
		return 4
	case store.FindingSeverityInfo:
		return 5
	default:
		return 6
	}
}

func findingTitle(issueType string) string {
	if t, ok := findingTitles[issueType]; ok {
		return t
	}
	return issueType
}

// findingTitles maps assessor issue_type values to human-readable card titles.
var findingTitles = map[string]string{
	"missing_spf":                  "No SPF record published",
	"weak_spf_policy":              "SPF policy too permissive (?all)",
	"soft_fail_spf_policy":         "SPF uses soft-fail (~all)",
	"missing_mechanisms":           "SPF specifies no senders",
	"missing_all_mechanism":        "SPF missing an 'all' mechanism",
	"excessive_lookups":            "SPF exceeds the 10-lookup limit",
	"spf_compliant":                "SPF correctly configured",
	"missing_dkim":                 "No DKIM records found",
	"weak_key_length":              "DKIM key too weak",
	"test_mode_enabled":            "DKIM in test mode",
	"dkim_compliant":               "DKIM correctly configured",
	"missing_dmarc":                "No DMARC policy published",
	"weak_dmarc_policy":            "DMARC policy set to p=none",
	"dmarc_missing_tags":           "DMARC missing rua/ruf tags",
	"dmarc_compliant":              "DMARC correctly configured",
	"not_applicable":               "Not applicable — domain doesn't handle email",
	"zone_transfer_exposed":        "Zone transfer (AXFR) exposed",
	"zone_transfer_refused":        "Zone transfer refused",
	"caa_missing":                  "No CAA records published",
	"caa_allows_any_ca":            "CAA permits any CA to issue",
	"caa_untrusted_issuer":         "CAA authorises an unrecognised CA",
	"caa_unknown_critical_flag":    "CAA has an unknown critical property",
	"caa_conflicting_records":      "CAA issuance policy conflicts",
	"caa_required_for_cert":        "Cert-bearing domain has no CAA",
	"missing_iodef":                "CAA has no iodef reporting endpoint",
	"insufficient_nameservers":     "Fewer than two nameservers",
	"same_provider":                "All nameservers use one provider",
	"no_ipv6":                      "No nameserver reachable over IPv6",
	"ns_not_resolvable":            "Nameserver does not resolve",
	"ns_is_cname":                  "Nameserver is a CNAME (illegal)",
	"unreachable":                  "Nameserver is unreachable",
	"no_tcp_support":               "Nameserver doesn't answer over TCP",
	"no_edns_support":              "Nameserver doesn't support EDNS0",
	"high_latency":                 "Nameserver response is slow",
	"resolver_mismatch":            "Nameservers return divergent answers",
	"missing_apex_address":         "Apex has no A/AAAA record",
	"missing_ipv6":                 "No IPv6 (AAAA) at apex",
	"missing_soa":                  "No SOA record at apex",
	"missing_mx":                   "No MX record for a mail-intended domain",
	"soa_timers_out_of_range":      "SOA timers outside recommended ranges",
	"soa_serial_format":            "SOA serial not in YYYYMMDDnn format",
	"soa_mname_unresolvable":       "SOA primary master does not resolve",
	"soa_rname_malformed":          "SOA responsible-party address malformed",
	"permit_all_spf_policy":        "SPF permits all senders (+all)",
	"missing_tags":                 "DKIM missing recommended tags",
	"quarantine_dmarc_policy":      "DMARC set to quarantine (partial enforcement)",
	"dmarc_reduced_pct":            "DMARC applied to only part of mail (pct<100)",
	"dmarc_weak_subdomain_policy":  "DMARC subdomain policy is weaker",
	"bimi_compliant":               "BIMI correctly configured",
	"bimi_not_configured":          "BIMI not configured (optional)",
	"bimi_requires_enforced_dmarc": "BIMI requires enforced DMARC",
	"bimi_invalid_logo":            "BIMI logo URL invalid",
	"bimi_invalid_vmc":             "BIMI VMC certificate URL invalid",
}

// findingDescriptions holds static descriptions for findings whose body text is
// not carried on the row. Email findings store their description in the row's
// details column; only zone-transfer findings rely on these.
var findingDescriptions = map[string]string{
	"zone_transfer_exposed": "The nameserver allowed a full zone transfer, exposing internal DNS records.",
	"zone_transfer_refused": "Nameserver correctly refused unsolicited zone-transfer requests.",
}

// findingFixes maps issue_type values to a short remediation hint. Issue types
// with no entry render without a fix line.
var findingFixes = map[string]string{
	"missing_spf":                  "Publish an SPF record, e.g. v=spf1 include:_spf.provider.net -all",
	"soft_fail_spf_policy":         "Tighten ~all to -all once all senders are enumerated.",
	"weak_spf_policy":              "Replace ?all with -all (or ~all) to enforce the policy.",
	"missing_all_mechanism":        "End the SPF record with -all (or ~all).",
	"excessive_lookups":            "Flatten includes to stay within the 10 DNS-lookup limit.",
	"missing_dmarc":                "Publish v=DMARC1; p=none; rua=… then ramp to quarantine/reject.",
	"weak_dmarc_policy":            "Move the DMARC policy from p=none to p=quarantine or p=reject.",
	"dmarc_missing_tags":           "Add an rua= (and optionally ruf=) reporting address.",
	"missing_dkim":                 "Publish a DKIM key for your sending selector(s).",
	"weak_key_length":              "Re-issue the DKIM key at 2048 bits.",
	"test_mode_enabled":            "Remove t=y from the DKIM record once verified.",
	"zone_transfer_exposed":        "Restrict AXFR/IXFR to authorised secondary nameservers only.",
	"caa_missing":                  "Publish a CAA record, e.g. example.com. IN CAA 0 issue \"letsencrypt.org\"",
	"caa_required_for_cert":        "Add a CAA record authorising the CA that issues your certificate.",
	"caa_allows_any_ca":            "Add an issue property to restrict which CAs may issue certificates.",
	"caa_untrusted_issuer":         "Confirm the authorised CA is intended; remove unexpected issue entries.",
	"caa_unknown_critical_flag":    "Review the critical CAA property; conformant CAs will refuse issuance.",
	"caa_conflicting_records":      "Remove the no-issuance directive or the conflicting permissive issue entry.",
	"missing_iodef":                "Add an iodef property, e.g. 0 iodef \"mailto:security@example.com\".",
	"insufficient_nameservers":     "Publish at least two nameservers on separate networks (RFC 2182).",
	"same_provider":                "Add nameservers from a second DNS provider so one outage can't take the zone offline.",
	"no_ipv6":                      "Add AAAA glue for at least one nameserver so IPv6-only resolvers can reach the zone.",
	"ns_not_resolvable":            "Publish A/AAAA glue for the nameserver, or remove the stale delegation.",
	"ns_is_cname":                  "Point the NS record at a host with A/AAAA records, not a CNAME (RFC 2181).",
	"unreachable":                  "Ensure the nameserver answers DNS queries on UDP/53 and is correctly delegated.",
	"no_tcp_support":               "Allow DNS over TCP/53; it is required for large responses and DNSSEC.",
	"no_edns_support":              "Enable EDNS0 on the nameserver for modern DNS features and larger UDP responses.",
	"high_latency":                 "Investigate nameserver/network latency; consider anycast or a closer provider.",
	"resolver_mismatch":            "Reconcile zone data across nameservers; if mid-propagation, re-check after TTLs expire.",
	"missing_apex_address":         "Publish an A and/or AAAA record at the apex.",
	"missing_ipv6":                 "Add an AAAA record to make the apex reachable over IPv6.",
	"missing_soa":                  "Ensure the zone publishes a SOA record at its apex.",
	"missing_mx":                   "Publish an MX record, or an explicit null-MX (0 .) if the domain sends no mail.",
	"soa_timers_out_of_range":      "Adjust SOA refresh/retry/expire/minimum to RFC 1912 ranges.",
	"soa_mname_unresolvable":       "Ensure the SOA MNAME (primary master) resolves to an address.",
	"soa_rname_malformed":          "Set a valid SOA RNAME, e.g. hostmaster.example.com.",
	"permit_all_spf_policy":        "Replace '+all'/'all' with '-all' immediately; it lets anyone spoof the domain.",
	"missing_tags":                 "Add the recommended 'k=' key-type tag to the DKIM record.",
	"quarantine_dmarc_policy":      "Move the DMARC policy from p=quarantine to p=reject for full enforcement.",
	"dmarc_reduced_pct":            "Remove pct< (or raise to 100) so the policy applies to all mail.",
	"dmarc_weak_subdomain_policy":  "Raise sp= to match the domain policy (e.g. sp=reject).",
	"bimi_requires_enforced_dmarc": "Enforce DMARC (p=quarantine or p=reject) before publishing BIMI.",
	"bimi_invalid_logo":            "Point BIMI l= at an HTTPS URL serving an SVG Tiny PS logo.",
	"bimi_invalid_vmc":             "Point BIMI a= at an HTTPS URL serving the VMC certificate.",
}
