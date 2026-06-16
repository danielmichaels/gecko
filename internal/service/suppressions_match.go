package service

import (
	"time"

	"github.com/danielmichaels/gecko/internal/store"
)

// suppressionMatches reports whether a single suppression row hides the finding
// identified by (domainID, kind, issueType, findingUID). It is the Go mirror of
// the SQL predicate used by FindingsListByTenant, DomainsListFindingsSummary and
// TenantFindingStatsAll — the two MUST stay in lockstep (a shared table-driven
// test pins them), so keep this logic equality-only:
//
//   - an ack (finding_uid set) matches that one finding instance by uid;
//   - a rule (finding_uid NULL) matches by kind+issue_type, with a NULL domain_id
//     acting as a tenant-global wildcard and a set domain_id scoping to one domain;
//   - an expired row (expires_at in the past) never matches.
//
// Tenant scope is NOT checked here: callers load suppressions already scoped to
// the tenant (and, for the per-domain path, to the domain) via the store query.
func suppressionMatches(
	s store.FindingSuppressions,
	now time.Time,
	domainID int32,
	kind, issueType, findingUID string,
) bool {
	if s.ExpiresAt.Valid && !s.ExpiresAt.Time.After(now) {
		return false
	}
	if s.FindingUid.Valid {
		// Ack: match the specific finding instance by uid.
		return findingUID != "" && s.FindingUid.String == findingUID
	}
	// Rule: match the check identity, tenant-global (NULL domain) or per-domain.
	if !s.Kind.Valid || !s.IssueType.Valid {
		return false
	}
	if s.Kind.String != kind || s.IssueType.String != issueType {
		return false
	}
	return !s.DomainID.Valid || s.DomainID.Int32 == domainID
}

// anySuppressionMatches reports whether any active suppression in the set hides
// the finding. The set comes from SuppressionsListActiveByDomain (tenant-global
// rules + the domain's own rules and acks).
func anySuppressionMatches(
	sups []store.FindingSuppressions,
	now time.Time,
	domainID int32,
	kind, issueType, findingUID string,
) bool {
	for i := range sups {
		if suppressionMatches(sups[i], now, domainID, kind, issueType, findingUID) {
			return true
		}
	}
	return false
}
