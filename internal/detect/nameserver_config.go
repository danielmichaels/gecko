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

func (d NameserverConfigDetector) Detect(
	ev NameserverConfigEvidence,
) (checks.DetectResult, error) {
	var res checks.DetectResult

	for _, ns := range ev.Nameservers {
		switch ns.CNAMEStatus {
		case ResolutionData:
			res.Found = append(res.Found, checks.Finding{
				IssueType: IssueNSIsCNAME,
				EntityKey: ns.Host,
				Severity:  "medium",
				Title:     "Nameserver is a CNAME",
				Details:   "Nameserver target is a CNAME, which is illegal for NS records (RFC 2181 §10.3)",
			})
		case ResolutionIndeterminate:
			res.Indeterminate = append(res.Indeterminate,
				checks.Key{IssueType: IssueNSIsCNAME, EntityKey: ns.Host})
		}

		if ns.CNAMEStatus != ResolutionData {
			switch {
			case ns.AStatus == ResolutionEmpty && ns.AAAAStatus == ResolutionEmpty:
				res.Found = append(res.Found, checks.Finding{
					IssueType: IssueNSNotResolvable,
					EntityKey: ns.Host,
					Severity:  "medium",
					Title:     "Nameserver does not resolve",
					Details:   "Nameserver does not resolve to any A or AAAA address (missing glue or lame delegation)",
				})
			case ns.AStatus != ResolutionData && ns.AAAAStatus != ResolutionData:
				// Neither resolves nor authoritatively empty: an address lookup was
				// indeterminate, so resolvability is unknown -- protect the key.
				res.Indeterminate = append(res.Indeterminate,
					checks.Key{IssueType: IssueNSNotResolvable, EntityKey: ns.Host})
			}
		}

		if !ns.InBailiwick {
			switch ns.ApexStatus {
			case ResolutionEmpty:
				res.Found = append(res.Found, checks.Finding{
					IssueType: IssueDanglingNS,
					EntityKey: ns.Host,
					Severity:  "high",
					Title:     "Dangling nameserver delegation",
					Details: fmt.Sprintf(
						"Nameserver parent domain %q does not exist (NXDOMAIN); it may be registerable and used to hijack this delegation",
						nsProviderApex(ns.Host),
					),
				})
			case ResolutionIndeterminate:
				res.Indeterminate = append(res.Indeterminate,
					checks.Key{IssueType: IssueDanglingNS, EntityKey: ns.Host})
			}
		}
	}

	count := len(ev.Nameservers)
	if count < d.RecommendedCount {
		res.Found = append(res.Found, checks.Finding{
			IssueType: IssueInsufficientNameservers,
			Severity:  "high",
			Title:     "Insufficient nameservers",
			Details: fmt.Sprintf(
				"Domain delegates to only %d nameserver(s); RFC 2182 recommends at least %d",
				count, d.RecommendedCount,
			),
		})
	} else if distinctProviders(ev.Nameservers) <= 1 {
		res.Found = append(res.Found, checks.Finding{
			IssueType: IssueSameProvider,
			Severity:  "medium",
			Title:     "Single nameserver provider",
			Details:   "All nameservers belong to a single provider; an outage there takes the entire zone offline",
		})
	}

	if count > 0 && !anyIPv6(ev.Nameservers) {
		// "No IPv6" is authoritative only when every AAAA lookup actually completed.
		// If any AAAA lookup was indeterminate, we cannot claim the set lacks IPv6.
		if anyAAAAIndeterminate(ev.Nameservers) {
			res.Indeterminate = append(res.Indeterminate, checks.Key{IssueType: IssueNoIPv6})
		} else {
			res.Found = append(res.Found, checks.Finding{
				IssueType: IssueNoIPv6,
				Severity:  "low",
				Title:     "No IPv6 nameserver coverage",
				Details:   "No nameserver in the set is reachable over IPv6; IPv6-only resolvers cannot reach the zone",
			})
		}
	}

	return res, nil
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

// anyAAAAIndeterminate reports whether any nameserver's AAAA lookup failed to
// complete, so a "no IPv6" verdict over the set would be unsafe.
func anyAAAAIndeterminate(nss []NameserverEvidence) bool {
	for _, ns := range nss {
		if ns.AAAAStatus == ResolutionIndeterminate {
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
