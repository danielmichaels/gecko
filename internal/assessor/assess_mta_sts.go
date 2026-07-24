package assessor

import (
	"strings"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/miekg/dns"
)

// mtaStsMinMaxAge is the policy max_age (seconds) below which MTA-STS offers weak
// protection: a short window lets a downgrade attacker wait out the cached policy.
// RFC 8461 recommends at least a few weeks; one week is the minimum we accept.
const mtaStsMinMaxAge = 604800

func (a *Assessor) lookupTXTPrefixed(name, prefix string) (string, dnsclient.ResolutionStatus) {
	records, status := a.dnsClient.LookupWithStatus(name, dns.TypeTXT)
	if status != dnsclient.ResolutionData {
		return "", status
	}
	for _, r := range records {
		if strings.HasPrefix(strings.TrimSpace(r), prefix) {
			return r, status
		}
	}
	return "", status
}
