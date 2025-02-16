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
		//w.logger.DebugContext(w.ctx, "no CNAME", "domain", domain.Name)
		//_ = m.Nak()
		return &res
	}
	if len(cname) > 0 {
		res.CNAME = cname
		a, ok := dc.LookupA(domain)
		if !ok {
			//w.logger.DebugContext(w.ctx, "no A record", "domain", domain)
			//_ = m.Nak()
			res.CNAME = nil
			//return &res
		}
		res.A = a
		aaaa, ok := dc.LookupAAAA(domain)
		if !ok {
			res.AAAA = nil
			//w.logger.DebugContext(w.ctx, "no A record", "domain", domain)
			//_ = m.Nak()
			//return &res
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
