package service

import (
	"context"
	"sort"
	"strings"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

type FindingsService struct {
	*Service
}

type FindingView struct {
	Kind        string
	Severity    string
	SevClass    string
	Tier        string
	Icon        string
	Title       string
	Description string
	Evidence    string
	FixHint     string
	DomainUID   string
	DomainName  string
	FindingUID  string
	FirstSeen   string
}

// FindingsResult is a domain's open findings, worst-first. There is no
// "healthy" bucket: under the collect/detect model a passing check emits no
// finding at all, so absence here means "clean, not applicable, or never
// scanned" — a distinction only check coverage can make.
type FindingsResult struct {
	Findings      []FindingView
	TotalCount    int
	CriticalCount int
	WarningCount  int
}

type FindingsListOptions struct {
	Severity         string
	Kind             string
	DomainQuery      string
	IncludeCompliant bool
}

type TenantFindingsResult struct {
	KindCounts     map[string]int
	SeverityCounts map[string]int
	Groups         []DomainFindingGroup
	Totals         FindingTotals
}

type DomainFindingGroup struct {
	DomainUID  string
	DomainName string
	Findings   []FindingView
	CritCount  int
	HighCount  int
	WarnCount  int
	LowCount   int
}

type FindingTotals struct {
	Open        int
	Critical    int
	High        int
	Medium      int
	Low         int
	DomainCount int
}

type FlatFindingsResult struct {
	Findings   []FindingView
	TotalCount int64
}

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

	rows, err := s.DB.FindingsListByDomainUID(ctx, store.FindingsListByDomainUIDParams{
		Uid:      domainUID,
		TenantID: p.TenantID,
	})
	if err != nil {
		return FindingsResult{}, err
	}

	findings := make([]FindingView, 0, len(rows))
	for _, row := range rows {
		findings = append(findings, mapDomainFinding(row))
	}

	res := FindingsResult{Findings: findings, TotalCount: len(findings)}
	for _, f := range findings {
		switch f.SevClass {
		case "crit":
			res.CriticalCount++
		case "warn":
			res.WarningCount++
		}
	}
	return res, nil
}

func (s *FindingsService) ListByTenant(
	ctx context.Context,
	p *auth.Principal,
	opts FindingsListOptions,
) (TenantFindingsResult, error) {
	rows, err := s.DB.FindingsListTenantOpen(ctx, p.TenantID)
	if err != nil {
		return TenantFindingsResult{}, err
	}
	return buildTenantFindings(rows, opts), nil
}

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

func buildTenantFindings(
	rows []store.FindingsListTenantOpenRow,
	opts FindingsListOptions,
) TenantFindingsResult {
	res := TenantFindingsResult{
		KindCounts:     map[string]int{},
		SeverityCounts: map[string]int{},
	}
	query := strings.ToLower(strings.TrimSpace(opts.DomainQuery))
	groupIndex := make(map[string]int, len(rows))

	for _, row := range rows {
		f := mapTenantFinding(row)

		if query != "" && !strings.Contains(strings.ToLower(f.DomainName), query) {
			continue
		}
		matchSev := opts.Severity == "" || f.Tier == opts.Severity
		matchKind := opts.Kind == "" || f.Kind == opts.Kind

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

func newFindingView(
	checkKind, issueType, severity, title, details, findingUID string,
	evidence []byte,
	seenAt pgtype.Timestamptz,
) FindingView {
	class := severityClass(severity)
	return FindingView{
		Kind:        checkKind,
		Severity:    severity,
		SevClass:    class,
		Tier:        severityTier(severity),
		Icon:        severityIcon(class),
		Title:       title,
		Description: details,
		Evidence:    evidenceString(evidence),
		FixHint:     findingFixes[issueType],
		FindingUID:  findingUID,
		FirstSeen:   firstSeen(seenAt),
	}
}

func mapDomainFinding(f store.Findings) FindingView {
	return newFindingView(
		f.CheckKind,
		f.IssueType,
		f.Severity,
		f.Title,
		f.Details,
		f.Uid,
		f.Evidence,
		f.FirstSeen,
	)
}

func mapTenantFinding(row store.FindingsListTenantOpenRow) FindingView {
	v := newFindingView(
		row.CheckKind,
		row.IssueType,
		row.Severity,
		row.Title,
		row.Details,
		row.FindingUid,
		row.Evidence,
		row.FirstSeen,
	)
	v.DomainUID = row.DomainUid
	v.DomainName = row.DomainName
	return v
}

// findingFixes maps a detector's issue_type to a short remediation hint. Copy
// lives here rather than on checks.Finding so it stays reviewable in one place
// and can be edited without a rescan. An issue type with no entry renders
// without a fix line; findings_fixhint_test.go fails the build if one appears.
var findingFixes = map[string]string{
	"missing_spf":                   "Publish an SPF record, e.g. v=spf1 include:_spf.provider.net -all",
	"soft_fail_spf_policy":          "Tighten ~all to -all once all senders are enumerated.",
	"weak_spf_policy":               "Replace ?all with -all (or ~all) to enforce the policy.",
	"missing_all_mechanism":         "End the SPF record with -all (or ~all).",
	"missing_mechanisms":            "Add at least one sending mechanism (include:, a, mx, ip4:, ip6:) or publish v=spf1 -all if the domain sends no mail.",
	"excessive_lookups":             "Flatten includes to stay within the 10 DNS-lookup limit.",
	"permit_all_spf_policy":         "Replace '+all'/'all' with '-all' immediately; it lets anyone spoof the domain.",
	"missing_dmarc":                 "Publish v=DMARC1; p=none; rua=… then ramp to quarantine/reject.",
	"weak_dmarc_policy":             "Move the DMARC policy from p=none to p=quarantine or p=reject.",
	"quarantine_dmarc_policy":       "Move the DMARC policy from p=quarantine to p=reject for full enforcement.",
	"dmarc_missing_tags":            "Add an rua= (and optionally ruf=) reporting address.",
	"dmarc_reduced_pct":             "Remove pct< (or raise to 100) so the policy applies to all mail.",
	"dmarc_weak_subdomain_policy":   "Raise sp= to match the domain policy (e.g. sp=reject).",
	"missing_dkim":                  "Publish a DKIM key for your sending selector(s).",
	"weak_key_length":               "Re-issue the DKIM key at 2048 bits.",
	"test_mode_enabled":             "Remove t=y from the DKIM record once verified.",
	"missing_tags":                  "Add the recommended 'k=' key-type tag to the DKIM record.",
	"bimi_requires_enforced_dmarc":  "Enforce DMARC (p=quarantine or p=reject) before publishing BIMI.",
	"bimi_invalid_logo":             "Point BIMI l= at an HTTPS URL serving an SVG Tiny PS logo.",
	"bimi_invalid_vmc":              "Point BIMI a= at an HTTPS URL serving the VMC certificate.",
	"mta_sts_policy_unreachable":    "Serve the policy at https://mta-sts.<domain>/.well-known/mta-sts.txt over HTTPS.",
	"mta_sts_mode_not_enforcing":    "Set mode: enforce in the MTA-STS policy once testing confirms delivery.",
	"mta_sts_mx_mismatch":           "List every published MX host in the MTA-STS policy mx: lines.",
	"mta_sts_short_max_age":         "Raise the MTA-STS policy max_age to at least 604800 (one week).",
	"tls_rpt_invalid_rua":           "Set a valid TLS-RPT rua endpoint, e.g. rua=mailto:tls-reports@example.com.",
	"zone_transfer_exposed":         "Restrict AXFR/IXFR to authorised secondary nameservers only.",
	"caa_missing":                   "Publish a CAA record, e.g. example.com. IN CAA 0 issue \"letsencrypt.org\"",
	"caa_required_for_cert":         "Add a CAA record authorising the CA that issues your certificate.",
	"caa_allows_any_ca":             "Add an issue property to restrict which CAs may issue certificates.",
	"caa_untrusted_issuer":          "Confirm the authorised CA is intended; remove unexpected issue entries.",
	"caa_unknown_critical_flag":     "Review the critical CAA property; conformant CAs will refuse issuance.",
	"caa_conflicting_records":       "Remove the no-issuance directive or the conflicting permissive issue entry.",
	"missing_iodef":                 "Add an iodef property, e.g. 0 iodef \"mailto:security@example.com\".",
	"certificate_expiry":            "Renew the certificate and automate renewal (e.g. ACME) so it cannot lapse again.",
	"certificate_weak_key":          "Re-issue the certificate with a 2048-bit RSA key or a P-256 ECDSA key.",
	"certificate_self_signed":       "Replace the self-signed certificate with one issued by a publicly trusted CA.",
	"certificate_hostname_mismatch": "Re-issue the certificate with this hostname in its SAN list, or serve the certificate that matches.",
	"dnssec_broken_chain":           "Re-publish the DS record at the registrar so it matches the zone's current DNSKEY.",
	"dnssec_weak_algorithm":         "Roll the zone to a modern signing algorithm (ECDSAP256SHA256 or Ed25519).",
	"dangling_cname":                "Remove the CNAME or reclaim its target; an unclaimed target can be registered by an attacker to take over this hostname.",
	"points_to_ip":                  "Point the CNAME at a hostname; use an A/AAAA record to publish an address directly.",
	"cname_loop":                    "Break the CNAME loop; a chain must terminate at a record holding an address.",
	"long_chain":                    "Flatten the CNAME chain; every hop adds a lookup, latency, and a failure point.",
	"insufficient_nameservers":      "Publish at least two nameservers on separate networks (RFC 2182).",
	"same_provider":                 "Add nameservers from a second DNS provider so one outage can't take the zone offline.",
	"no_ipv6":                       "Add AAAA glue for at least one nameserver so IPv6-only resolvers can reach the zone.",
	"ns_not_resolvable":             "Publish A/AAAA glue for the nameserver, or remove the stale delegation.",
	"ns_is_cname":                   "Point the NS record at a host with A/AAAA records, not a CNAME (RFC 2181).",
	"dangling_ns":                   "Remove the stale delegation or re-point it; the nameserver's parent domain no longer exists and could be re-registered by an attacker.",
	"unreachable":                   "Ensure the nameserver answers DNS queries on UDP/53 and is correctly delegated.",
	"no_tcp_support":                "Allow DNS over TCP/53; it is required for large responses and DNSSEC.",
	"no_edns_support":               "Enable EDNS0 on the nameserver for modern DNS features and larger UDP responses.",
	"high_latency":                  "Investigate nameserver/network latency; consider anycast or a closer provider.",
	"resolver_mismatch":             "Reconcile zone data across nameservers; if mid-propagation, re-check after TTLs expire.",
	"missing_apex_address":          "Publish an A and/or AAAA record at the apex.",
	"missing_ipv6":                  "Add an AAAA record to make the apex reachable over IPv6.",
	"missing_soa":                   "Ensure the zone publishes a SOA record at its apex.",
	"missing_mx":                    "Publish an MX record, or an explicit null-MX (0 .) if the domain sends no mail.",
	"soa_timers_out_of_range":       "Adjust SOA refresh/retry/expire/minimum to RFC 1912 ranges.",
	"soa_mname_unresolvable":        "Ensure the SOA MNAME (primary master) resolves to an address.",
	"soa_rname_malformed":           "Set a valid SOA RNAME, e.g. hostmaster.example.com.",
	"soa_serial_format":             "Use a monotonically increasing SOA serial; the YYYYMMDDnn convention makes staleness obvious.",
}

func evidenceString(evidence []byte) string {
	if len(evidence) == 0 {
		return ""
	}
	return string(evidence)
}

func firstSeen(ts pgtype.Timestamptz) string {
	if !ts.Valid {
		return ""
	}
	return ts.Time.Format("2006-01-02")
}

func severityTier(severity string) string {
	switch severity {
	case "critical":
		return "crit"
	case "high":
		return "high"
	case "medium":
		return "med"
	case "low":
		return "low"
	default:
		return "ok"
	}
}

func severityClass(severity string) string {
	switch severity {
	case "critical", "high":
		return "crit"
	case "medium", "low":
		return "warn"
	default:
		return "info"
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
