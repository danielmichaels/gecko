package scanner

import "github.com/miekg/dns"

type ZoneTransferResult struct {
	Domain                string
	NS                    []string
	AXFR                  map[string][]dns.RR
	IXFR                  map[string][]dns.RR
	Error                 string
	Vulnerable            bool
	SuccessfulTransfers   map[string]string
	VulnerableNameservers []string
}

func NewZoneTransferResult(domain string) *ZoneTransferResult {
	return &ZoneTransferResult{
		Domain:                domain,
		AXFR:                  make(map[string][]dns.RR),
		IXFR:                  make(map[string][]dns.RR),
		SuccessfulTransfers:   make(map[string]string),
		VulnerableNameservers: make([]string, 0),
	}
}

func ScanZoneTransfer(domain string) *ZoneTransferResult {
	client := NewDNSClient()
	result := client.AttemptZoneTransfer(domain)
	return result
}
