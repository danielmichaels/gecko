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
	Kind        string // the detector's check_kind, e.g. email_security | certificate | zone_transfer
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
// for the summary strip (info collapses into "healthy").
type FindingsResult struct {
	Findings      []FindingView
	TotalCount    int
	CriticalCount int
	WarningCount  int
	HealthyCount  int
}

// FindingsListOptions narrows a tenant-wide findings listing. Empty strings mean
// "no filter". Severity is a single 4-tier value (crit|high|med|low) to match the
// single-select UI; Kind is the detector's check_kind; DomainQuery is a
// case-insensitive substring match on the domain name. IncludeCompliant is
// retained for API/UI compatibility but is a no-op: the generic findings table
// only ever holds actionable (open) rows, so there is nothing "compliant" to
// include or exclude.
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

// ListByDomain returns a domain's open findings, worst-first. Returns
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

	rows, err := s.DB.FindingsListByDomainUID(ctx, store.FindingsListByDomainUIDParams{
		Uid:      domainUID,
		TenantID: p.TenantID,
	})
	if err != nil {
		return FindingsResult{}, err
	}

	// Rows arrive worst-first from FindingsListByDomainUID's ORDER BY; no Go-side
	// re-sort needed.
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
		default: // info reads as "healthy" in the summary strip
			res.HealthyCount++
		}
	}
	return res, nil
}

// ListByTenant rolls up every open finding across the caller's domains into a
// grouped, filtered, worst-first view. Tenant isolation is enforced by the SQL
// join-gate in FindingsListTenantOpen — never by a Go-side tenant filter.
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

// ListByTenantFlat returns the tenant-wide findings as a flat, worst-first,
// paginated slice for the REST API. It reuses ListByTenant's tenant-gated SQL,
// filtering and worst-first ordering, then flattens the per-domain groups.
//
// FLAG: FindingsListTenantOpen returns every open finding for the tenant in one
// query; finding counts per tenant are bounded (the detector writes ~1 row per
// check per asset), so pagination here is an in-memory slice. For tenants with
// O(10k+) domains this should move to SQL-level LIMIT/OFFSET.
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
// tenant rows (which arrive pre-sorted domain-then-severity). Separated from the
// DB call so it is exhaustively unit-testable with synthetic rows.
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

// newFindingView builds the presentation view shared by the per-domain and
// tenant-wide reads; the tenant read sets DomainUID/DomainName on the result.
func newFindingView(
	checkKind, severity, title, details, findingUID string,
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
		FindingUID:  findingUID,
		FirstSeen:   firstSeen(seenAt),
	}
}

// mapDomainFinding maps a generic findings row (per-domain read) to a FindingView.
func mapDomainFinding(f store.Findings) FindingView {
	return newFindingView(
		f.CheckKind,
		f.Severity,
		f.Title,
		f.Details,
		f.Uid,
		f.Evidence,
		f.FirstSeen,
	)
}

// mapTenantFinding maps a FindingsListTenantOpen row (tenant-wide read, carrying
// domain identity) to a FindingView.
func mapTenantFinding(row store.FindingsListTenantOpenRow) FindingView {
	v := newFindingView(
		row.CheckKind,
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

// evidenceString renders a finding's JSONB evidence column as a string, empty
// when the column is unset.
func evidenceString(evidence []byte) string {
	if len(evidence) == 0 {
		return ""
	}
	return string(evidence)
}

// firstSeen renders a finding's first-seen timestamp as a plain date.
func firstSeen(ts pgtype.Timestamptz) string {
	if !ts.Valid {
		return ""
	}
	return ts.Time.Format("2006-01-02")
}

// severityTier maps a finding severity to the 4-tier class used by the
// tenant-wide Findings screen (distinct from the 2-tier severityClass that the
// per-domain card uses). Info and anything unknown read as "ok".
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

// severityClass maps a finding's severity to a 2-tier UI badge class. Every row
// read here is already status='open', so critical/high/medium/low always read as
// actionable; info (and anything unrecognised) reads as "info" rather than "ok" —
// the healthy/ok bucket is for domains with no finding row at all.
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
