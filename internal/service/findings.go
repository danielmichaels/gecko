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

type FindingsResult struct {
	Findings      []FindingView
	TotalCount    int
	CriticalCount int
	WarningCount  int
	HealthyCount  int
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
		default:
			res.HealthyCount++
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
