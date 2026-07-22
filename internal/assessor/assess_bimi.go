package assessor

import "strings"

func (a *Assessor) lookupBIMIRecord(domainName string) string {
	records, found := a.dnsClient.LookupTXT("default._bimi." + domainName)
	if !found {
		return ""
	}
	for _, r := range records {
		if strings.HasPrefix(strings.TrimSpace(r), "v=BIMI1") {
			return r
		}
	}
	return ""
}
