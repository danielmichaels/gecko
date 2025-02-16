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

// getDNSServer returns the DNS server to be used for DNS lookups. It first checks the configuration for a custom
// DNS server, and if none is set, it defaults to "8.8.8.8:53" (Google's public DNS server).
func getDNSServers() []string {
	var servers []string
	// Get custom servers from environment
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
				}
			}
		}
		return result, true
	}
	return nil, false
}

type SubdomainResult struct {
	Name  string
	A     []string
	AAAA  []string
	CNAME []string
	MX    []string
	TXT   []string
	NS    []string
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
	//fmt.Printf("%v\n", sourceMap)

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
		} {
			if records, ok := c.lookupRecord(subdomain+".", query.qtype); ok && len(records) > 0 {
				*query.field = records
			}
		}
		if len(result.A) > 0 || len(result.AAAA) > 0 || len(result.CNAME) > 0 ||
			len(result.MX) > 0 || len(result.NS) > 0 || len(result.TXT) > 0 {
			enrichedResults = append(enrichedResults, result)
		}
	}
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
	for _, record := range result.A {
		fmt.Printf("A record for %s: %s\n", result.Name, record)
	}
	for _, record := range result.AAAA {
		fmt.Printf("AAAA record for %s: %s\n", result.Name, record)
	}
	for _, record := range result.MX {
		fmt.Printf("MX record for %s: %s\n", result.Name, record)
	}
	for _, record := range result.NS {
		fmt.Printf("NS record for %s: %s\n", result.Name, record)
	}
	for _, record := range result.CNAME {
		fmt.Printf("CNAME record for %s: %s\n", result.Name, record)
	}
	for _, record := range result.TXT {
		fmt.Printf("TXT record for %s: %s\n", result.Name, record)
	}
	return nil
}
