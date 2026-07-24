package assessor

import (
	"strings"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/miekg/dns"
)

func (a *Assessor) lookupBIMIRecord(domainName string) (string, dnsclient.ResolutionStatus) {
	records, status := a.dnsClient.LookupWithStatus("default._bimi."+domainName, dns.TypeTXT)
	if status != dnsclient.ResolutionData {
		return "", status
	}
	for _, r := range records {
		if strings.HasPrefix(strings.TrimSpace(r), "v=BIMI1") {
			return r, status
		}
	}
	return "", status
}
