package assessor

import (
	"strings"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/miekg/dns"
)

// mtaStsMinMaxAge is the one-week minimum accepted policy lifetime.
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
