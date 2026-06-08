package service

import (
	"context"
	"sort"

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
	Kind        string // SPF | DKIM | DMARC | ZoneTransfer
	Severity    string // critical | high | medium | low | info
	SevClass    string // crit | warn | info | ok
	Icon        string // glyph for the card icon
	Title       string
	Description string
	Evidence    string
	FixHint     string
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

// ListByDomain aggregates the four implemented finding types (SPF, DKIM, DMARC,
// zone transfer) for a domain into a single severity-sorted list. Returns
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

	if spf, err := s.DB.AssessGetSPFFindingByDomainID(ctx, domainUID); err == nil {
		for _, f := range spf {
			findings = append(findings, mapEmailFinding(
				"SPF", f.Severity, f.Status, f.IssueType, f.Details, f.SpfValue,
			))
		}
	}
	if dkim, err := s.DB.AssessDKIMFindingsByDomainID(ctx, domainUID); err == nil {
		for _, f := range dkim {
			findings = append(findings, mapEmailFinding(
				"DKIM", f.Severity, f.Status, f.IssueType, f.Details, f.DkimValue,
			))
		}
	}
	if dmarc, err := s.DB.AssessGetDMARCFindingsByDomainID(ctx, domainUID); err == nil {
		for _, f := range dmarc {
			findings = append(findings, mapEmailFinding(
				"DMARC", f.Severity, f.Status, f.IssueType, f.Details, f.DmarcValue,
			))
		}
	}
	if zones, err := s.DB.AssessGetZoneTransferFindingsByDomainUID(ctx, domainUID); err == nil {
		for _, f := range zones {
			findings = append(findings, mapZoneTransferFinding(f))
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

// mapEmailFinding maps an SPF/DKIM/DMARC finding row to a FindingView.
func mapEmailFinding(
	kind string,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType string,
	details, value pgtype.Text,
) FindingView {
	class := severityClass(severity, status)
	return FindingView{
		Kind:        kind,
		Severity:    string(severity),
		SevClass:    class,
		Icon:        severityIcon(class),
		Title:       findingTitle(issueType),
		Description: details.String,
		Evidence:    value.String,
		FixHint:     findingFixes[issueType],
	}
}

// mapZoneTransferFinding maps a zone-transfer finding. A refused transfer is
// healthy regardless of its stored severity; only an actually-possible AXFR is a
// real exposure.
func mapZoneTransferFinding(f store.ZoneTransferFindings) FindingView {
	class := severityClass(f.Severity, f.Status)
	title := "Zone transfer refused"
	desc := "Nameserver correctly refused unsolicited zone-transfer requests."
	fix := ""
	evidence := f.Nameserver + " — REFUSED"

	if f.ZoneTransferPossible {
		title = "Zone transfer (AXFR) exposed"
		desc = "The nameserver allowed a full zone transfer, exposing internal DNS records."
		fix = "Restrict AXFR/IXFR to authorised secondary nameservers only."
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
		Icon:        severityIcon(class),
		Title:       title,
		Description: desc,
		Evidence:    evidence,
		FixHint:     fix,
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
	"missing_spf":           "No SPF record published",
	"weak_spf_policy":       "SPF policy too permissive (?all)",
	"soft_fail_spf_policy":  "SPF uses soft-fail (~all)",
	"missing_mechanisms":    "SPF specifies no senders",
	"missing_all_mechanism": "SPF missing an 'all' mechanism",
	"excessive_lookups":     "SPF exceeds the 10-lookup limit",
	"spf_compliant":         "SPF correctly configured",
	"missing_dkim":          "No DKIM records found",
	"weak_key_length":       "DKIM key too weak",
	"test_mode_enabled":     "DKIM in test mode",
	"dkim_compliant":        "DKIM correctly configured",
	"missing_dmarc":         "No DMARC policy published",
	"weak_dmarc_policy":     "DMARC policy set to p=none",
	"dmarc_missing_tags":    "DMARC missing rua/ruf tags",
	"dmarc_compliant":       "DMARC correctly configured",
	"not_applicable":        "Not applicable — domain doesn't handle email",
}

// findingFixes maps issue_type values to a short remediation hint. Issue types
// with no entry render without a fix line.
var findingFixes = map[string]string{
	"missing_spf":           "Publish an SPF record, e.g. v=spf1 include:_spf.provider.net -all",
	"soft_fail_spf_policy":  "Tighten ~all to -all once all senders are enumerated.",
	"weak_spf_policy":       "Replace ?all with -all (or ~all) to enforce the policy.",
	"missing_all_mechanism": "End the SPF record with -all (or ~all).",
	"excessive_lookups":     "Flatten includes to stay within the 10 DNS-lookup limit.",
	"missing_dmarc":         "Publish v=DMARC1; p=none; rua=… then ramp to quarantine/reject.",
	"weak_dmarc_policy":     "Move the DMARC policy from p=none to p=quarantine or p=reject.",
	"dmarc_missing_tags":    "Add an rua= (and optionally ruf=) reporting address.",
	"missing_dkim":          "Publish a DKIM key for your sending selector(s).",
	"weak_key_length":       "Re-issue the DKIM key at 2048 bits.",
	"test_mode_enabled":     "Remove t=y from the DKIM record once verified.",
}
