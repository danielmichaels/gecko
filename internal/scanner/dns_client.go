package scanner

import (
	"bytes"
	"context"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/config"
	"io"
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
					result = append(result, x.Mbox)
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

// EnumerateWithSubfinder performs a subdomain enumeration using the subfinder tool
// and returns the results as a slice of SubdomainResult structs.
func (c *DNSClient) EnumerateWithSubfinder(
	ctx context.Context,
	domain string,
	concurrency int,
) ([]SubdomainResult, error) {
	return c.enumerateWithSubfinder(ctx, domain, concurrency)
}
func (c *DNSClient) enumerateWithSubfinder(
	ctx context.Context,
	domain string,
	concurrency int,
) ([]SubdomainResult, error) {
	// Start with original domain lookup
	originalDomain := SubdomainResult{
		Name: domain,
	}

	// Get all DNS records for original domain
	for _, query := range []struct {
		field *[]string
		qtype uint16
	}{
		{&originalDomain.A, dns.TypeA},
		{&originalDomain.AAAA, dns.TypeAAAA},
		{&originalDomain.CNAME, dns.TypeCNAME},
		{&originalDomain.MX, dns.TypeMX},
		{&originalDomain.TXT, dns.TypeTXT},
		{&originalDomain.NS, dns.TypeNS},
		{&originalDomain.PTR, dns.TypePTR},
		{&originalDomain.SRV, dns.TypeSRV},
		{&originalDomain.CAA, dns.TypeCAA},
		{&originalDomain.DNSKEY, dns.TypeDNSKEY},
		{&originalDomain.SOA, dns.TypeSOA},
	} {
		if records, ok := c.lookupRecord(domain+".", query.qtype); ok && len(records) > 0 {
			*query.field = records
		}
	}

	subfinderOpts := &runner.Options{
		Threads:            concurrency, // Thread controls the number of threads to use for active enumerations
		Timeout:            30,          // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 10,          // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Silent:             true,
		JSON:               false,
	}

	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return []SubdomainResult{}, fmt.Errorf("failed to create subfinder runner: %w", err)
	}

	output := &bytes.Buffer{}
	_, err = subfinder.EnumerateSingleDomainWithCtx(
		ctx,
		domain,
		[]io.Writer{output},
	)
	if err != nil {
		return []SubdomainResult{}, fmt.Errorf("failed to enumerate domain %s: %w", domain, err)
	}

	subdomains := strings.Split(output.String(), "\n")
	var enrichedResults []SubdomainResult

	for _, subdomain := range subdomains {
		if subdomain == "" {
			continue
		}
		result := SubdomainResult{
			Name: subdomain,
		}
		for _, query := range []struct {
			field *[]string
			qtype uint16
		}{
			{&result.A, dns.TypeA},
			{&result.AAAA, dns.TypeAAAA},
			{&result.CNAME, dns.TypeCNAME},
			{&result.MX, dns.TypeMX},
			{&result.TXT, dns.TypeTXT},
			{&result.NS, dns.TypeNS},
			{&result.PTR, dns.TypePTR},
			{&result.SRV, dns.TypeSRV},
			{&result.CAA, dns.TypeCAA},
			{&result.DNSKEY, dns.TypeDNSKEY},
			{&result.SOA, dns.TypeSOA},
		} {
			if records, ok := c.lookupRecord(subdomain+".", query.qtype); ok && len(records) > 0 {
				*query.field = records
			}
		}
		if len(result.A) > 0 || len(result.AAAA) > 0 || len(result.CNAME) > 0 ||
			len(result.MX) > 0 || len(result.NS) > 0 || len(result.TXT) > 0 ||
			len(result.PTR) > 0 || len(result.SOA) > 0 || len(result.DNSKEY) > 0 ||
			len(result.SRV) > 0 || len(result.CAA) > 0 {
			enrichedResults = append(enrichedResults, result)
		}
	}
	enrichedResults = append([]SubdomainResult{originalDomain}, enrichedResults...)
	return enrichedResults, nil
}

func ProcessSubdomainResults(results []SubdomainResult, handler func(SubdomainResult) error) error {
	for _, result := range results {
		if err := handler(result); err != nil {
			return fmt.Errorf("failed to process subdomain %s: %w", result.Name, err)
		}
	}
	return nil
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
