package scanner

import (
	"context"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/config"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"strings"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type DNSClient struct {
	client           *dns.Client
	servers          []string
	currentServerIdx int
}

func NewDNSClient() *DNSClient {
	return &DNSClient{
		servers:          getDNSServers(),
		client:           new(dns.Client),
		currentServerIdx: 0,
	}
}

// getDNSServers returns the slice of DNS servers to be used for DNS lookups.
// If no slice is set, it defaults to a single entry, "8.8.8.8:53" (Google's public DNS server).
func getDNSServers() []string {
	var servers []string
	if customServers := config.AppConfig().AppConf.DNSServers; len(customServers) > 0 {
		servers = append(servers, customServers...)
	}
	if len(servers) == 0 {
		servers = append(servers, "8.8.8.8:53")
	}
	return servers
}

// LookupCNAME performs a DNS lookup for the given target and returns the CNAME record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupCNAME(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeCNAME)
}

// LookupA performs a DNS lookup for the given target and returns the A record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupA(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeA)
}

// LookupAAAA performs a DNS lookup for the given target and returns the AAAA record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupAAAA(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeAAAA)
}

// LookupMX performs a DNS lookup for the given target and returns the MX record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupMX(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeMX)
}

// LookupTXT performs a DNS lookup for the given target and returns the TXT record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupTXT(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeTXT)
}

// LookupNS performs a DNS lookup for the given target and returns the NS record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupNS(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeNS)
}

// LookupSOA performs a DNS lookup for the given target and returns the record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupSOA(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeSOA)
}

// LookupPTR performs a DNS lookup for the given target and returns the record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupPTR(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypePTR)
}

// LookupSRV performs a DNS lookup for the given target and returns the record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupSRV(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeSRV)
}

// LookupCAA performs a DNS lookup for the given target and returns the record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupCAA(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeCAA)
}

// LookupDNSKEY performs a DNS lookup for the given target and returns the record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupDNSKEY(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeDNSKEY)
}

// lookupRecord performs a DNS lookup for the given target and query type, using the specified DNS server.
// It returns the results as a slice of strings, and a boolean indicating whether the lookup was successful.
func (c *DNSClient) lookupRecord(target string, qtype uint16) ([]string, bool) {
	m := new(dns.Msg)
	m.SetQuestion(target, qtype)
	m.RecursionDesired = true

	for i := 0; i < len(c.servers); i++ {
		serverIdx := (c.currentServerIdx + i) % len(c.servers)
		server := c.servers[serverIdx]

		r, _, err := c.client.Exchange(m, server)
		if err != nil {
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			continue
		}
		c.currentServerIdx = (serverIdx + 1) % len(c.servers)

		var result []string
		for _, a := range r.Answer {
			h := a.Header()
			if h.Rrtype == qtype {
				switch x := a.(type) {
				case *dns.CNAME:
					result = append(result, x.Target)
				case *dns.A:
					result = append(result, x.A.String())
				case *dns.AAAA:
					result = append(result, x.AAAA.String())
				case *dns.MX:
					result = append(result, fmt.Sprintf("%d %s", x.Preference, x.Mx))
				case *dns.TXT:
					result = append(result, strings.Join(x.Txt, " "))
				case *dns.NS:
					result = append(result, x.Ns)
				case *dns.SOA:
					result = append(result, fmt.Sprintf("%s %s %d %d %d %d %d",
						x.Ns,
						x.Mbox,
						x.Serial,
						x.Refresh,
						x.Retry,
						x.Expire,
						x.Minttl))
				case *dns.PTR:
					result = append(result, x.Ptr)
				case *dns.SRV:
					result = append(result, x.Target)
				case *dns.CAA:
					result = append(result, x.Value)
				case *dns.DNSKEY:
					result = append(result, x.PublicKey)
				}
			}
		}
		return result, true
	}
	return nil, false
}

type SubdomainResult struct {
	Name   string
	A      []string
	AAAA   []string
	CNAME  []string
	MX     []string
	TXT    []string
	NS     []string
	PTR    []string
	SRV    []string
	CAA    []string
	SOA    []string
	DNSKEY []string
}

func (c *DNSClient) EnumerateWithSubfinderCallback(
	ctx context.Context,
	domain string,
	concurrency int,
	callback func(*resolve.HostEntry),
) error {
	subfinderOpts := &runner.Options{
		Threads:            concurrency,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Silent:             true,
		JSON:               false,
		ResultCallback:     callback,
	}

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return fmt.Errorf("failed to create subfinder runner: %w", err)
	}

	_, err = subfinder.EnumerateSingleDomainWithCtx(ctx, domain, nil)
	return err
}

func RecordHandler(result SubdomainResult) error {
	records := []struct {
		name    string
		entries []string
	}{
		{"A", result.A},
		{"AAAA", result.AAAA},
		{"CNAME", result.CNAME},
		{"TXT", result.TXT},
		{"NS", result.NS},
		{"MX", result.MX},
		{"SOA", result.SOA},
		{"PTR", result.PTR},
		{"CAA", result.CAA},
		{"DNSKEY", result.DNSKEY},
		{"SRV", result.SRV},
	}

	for _, r := range records {
		for _, entry := range r.entries {
			// todo: insert record into database
			fmt.Printf("%s record for %s: %s\n", r.name, result.Name, entry)
		}
	}
	return nil
}
