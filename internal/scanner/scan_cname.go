package scanner

import (
	"strings"

	"github.com/danielmichaels/doublestag/internal/dnsclient"
)

type CNAMEScanResult struct {
	Domain string
	A      []string
	AAAA   []string
	CNAME  []string
}

func (s *Scan) ScanCNAME(domain string) *CNAMEScanResult {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	res := CNAMEScanResult{
		Domain: domain,
	}
	dc := dnsclient.NewDNSClient()
	cname, ok := dc.LookupCNAME(res.Domain)
	if !ok {
		return &res
	}
	if len(cname) > 0 {
		res.CNAME = cname
		a, _ := dc.LookupA(domain)
		res.A = a
		aaaa, _ := dc.LookupAAAA(domain)
		res.AAAA = aaaa
	}
	res.Domain = strings.TrimSuffix(res.Domain, ".")
	for i, cn := range res.CNAME {
		if strings.HasSuffix(cn, ".") {
			res.CNAME[i] = strings.TrimSuffix(cn, ".")
		}
	}
	return &res
}
