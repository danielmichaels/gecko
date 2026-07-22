package detect

import (
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/checks"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

const CheckNameserverConfig = "nameserver_config"

const (
	IssueNSIsCNAME       = "ns_is_cname"
	IssueNSNotResolvable = "ns_not_resolvable"
	IssueDanglingNS      = "dangling_ns"
	IssueSameProvider    = "same_provider"
	IssueNoIPv6          = "no_ipv6"
)

// NameserverEvidence is one delegated nameserver's collected live-resolution
// state. Statuses use the ResolutionData/Empty/Indeterminate tri-state so a
// SERVFAIL is never mistaken for authoritative absence. InBailiwick marks a
// nameserver under the assessed zone itself (its parent trivially exists, so the
// dangling check is skipped); ApexStatus is the parent-apex SOA outcome, only
// meaningful when out of bailiwick.
type NameserverEvidence struct {
	Host        string `json:"host"`
	CNAMEStatus string `json:"cname_status"`
	AStatus     string `json:"a_status"`
	AAAAStatus  string `json:"aaaa_status"`
	ApexStatus  string `json:"apex_status"`
	InBailiwick bool   `json:"in_bailiwick"`
}

type NameserverConfigEvidence struct {
	DomainName  string               `json:"domain_name"`
	Nameservers []NameserverEvidence `json:"nameservers"`
}

// NameserverConfigDetector flags per-nameserver misconfiguration (CNAME target,
// unresolvable, dangling delegation) and set-level redundancy gaps (too few,
// single provider, no IPv6). RecommendedCount is injected.
type NameserverConfigDetector struct {
	RecommendedCount int
}

func (NameserverConfigDetector) Kind() string                { return CheckNameserverConfig }
func (NameserverConfigDetector) Scope() checks.EvidenceScope { return checks.SingleAsset }

func (d NameserverConfigDetector) Detect(ev NameserverConfigEvidence) ([]checks.Finding, error) {
	var out []checks.Finding

	for _, ns := range ev.Nameservers {
		if ns.CNAMEStatus == ResolutionData {
			out = append(out, checks.Finding{
				IssueType: IssueNSIsCNAME,
				EntityKey: ns.Host,
				Severity:  "medium",
				Title:     "Nameserver is a CNAME",
				Details:   "Nameserver target is a CNAME, which is illegal for NS records (RFC 2181 §10.3)",
			})
		}
		if ns.AStatus == ResolutionEmpty && ns.AAAAStatus == ResolutionEmpty &&
			ns.CNAMEStatus != ResolutionData {
			out = append(out, checks.Finding{
				IssueType: IssueNSNotResolvable,
				EntityKey: ns.Host,
				Severity:  "medium",
				Title:     "Nameserver does not resolve",
				Details:   "Nameserver does not resolve to any A or AAAA address (missing glue or lame delegation)",
			})
		}
		if !ns.InBailiwick && ns.ApexStatus == ResolutionEmpty {
			out = append(out, checks.Finding{
				IssueType: IssueDanglingNS,
				EntityKey: ns.Host,
				Severity:  "high",
				Title:     "Dangling nameserver delegation",
				Details: fmt.Sprintf(
					"Nameserver parent domain %q does not exist (NXDOMAIN); it may be registerable and used to hijack this delegation",
					nsProviderApex(ns.Host),
				),
			})
		}
	}

	count := len(ev.Nameservers)
	if count < d.RecommendedCount {
		out = append(out, checks.Finding{
			IssueType: IssueInsufficientNameservers,
			Severity:  "high",
			Title:     "Insufficient nameservers",
			Details: fmt.Sprintf(
				"Domain delegates to only %d nameserver(s); RFC 2182 recommends at least %d",
				count, d.RecommendedCount,
			),
		})
	} else if distinctProviders(ev.Nameservers) <= 1 {
		out = append(out, checks.Finding{
			IssueType: IssueSameProvider,
			Severity:  "medium",
			Title:     "Single nameserver provider",
			Details:   "All nameservers belong to a single provider; an outage there takes the entire zone offline",
		})
	}

	if count > 0 && !anyIPv6(ev.Nameservers) {
		out = append(out, checks.Finding{
			IssueType: IssueNoIPv6,
			Severity:  "low",
			Title:     "No IPv6 nameserver coverage",
			Details:   "No nameserver in the set is reachable over IPv6; IPv6-only resolvers cannot reach the zone",
		})
	}

	return out, nil
}

// distinctProviders counts unique registrable apexes across the nameserver set,
// the v1 proxy for provider diversity.
func distinctProviders(nss []NameserverEvidence) int {
	providers := make(map[string]struct{}, len(nss))
	for _, ns := range nss {
		providers[nsProviderApex(ns.Host)] = struct{}{}
	}
	return len(providers)
}

func anyIPv6(nss []NameserverEvidence) bool {
	for _, ns := range nss {
		if ns.AAAAStatus == ResolutionData {
			return true
		}
	}
	return false
}

// nsProviderApex returns the registrable domain (eTLD+1) of a nameserver host,
// falling back to the bare host when the public-suffix lookup fails.
func nsProviderApex(host string) string {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	apex, err := publicsuffix.Domain(h)
	if err != nil || apex == "" {
		return h
	}
	return apex
}
