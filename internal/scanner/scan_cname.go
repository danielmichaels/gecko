package scanner

import "strings"

type ProcessingResult struct {
	Domain string
	A      []string
	AAAA   []string
	CNAME  []string
}

func ScanCNAME(domain string) *ProcessingResult {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	res := ProcessingResult{
		Domain: domain,
	}
	dc := NewDNSClient()
	cname, ok := dc.LookupCNAME(res.Domain)
	if !ok {
		return &res
	}
	if len(cname) > 0 {
		res.CNAME = cname
		a, ok := dc.LookupA(domain)
		if !ok {
			res.CNAME = nil
		}
		res.A = a
		aaaa, ok := dc.LookupAAAA(domain)
		if !ok {
			res.AAAA = nil
		}
		res.AAAA = aaaa
	}
	// Strip trailing dots from domains in results
	res.Domain = strings.TrimSuffix(res.Domain, ".")
	for i, cn := range res.CNAME {
		if strings.HasSuffix(cn, ".") {
			res.CNAME[i] = strings.TrimSuffix(cn, ".")
		}
	}
	return &res
}

// todo
// CNAME loop
// CNAME branching chain
// CNAME points at IP
