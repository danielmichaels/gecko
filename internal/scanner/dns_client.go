package scanner

import (
	"context"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/config"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"log/slog"
	"strconv"
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
	slog.Info("DNS servers", "servers", servers)
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

// LookupRRSIG performs a DNS lookup for the given target and returns the RRSIG
// record results as a slice of strings, along with a boolean indicating whether
// the lookup was successful.
func (c *DNSClient) LookupRRSIG(target string) ([]string, bool) {
	return c.lookupRecord(target, dns.TypeRRSIG)
}

// LookupDS performs a DNS lookup for the given target and returns the DS record results as a slice of strings,
// along with a boolean indicating whether the lookup was successful.
func (c *DNSClient) LookupDS(target string) ([]string, bool) {
	parent, err := c.GetParentZone(target)
	if err != nil {
		slog.Info("Error getting parent zone", "target", target, "error", err)
		return nil, false
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(target), dns.TypeDS)
	m.SetEdns0(4096, true)
	slog.Info("Querying DS records for parent zone", "parent", parent, "target", target)
	return c.lookupRecord(target, dns.TypeDS)
}

// lookupRecord performs a DNS lookup for the given target and query type, using the specified DNS server.
// It returns the results as a slice of strings, and a boolean indicating whether the lookup was successful.
func (c *DNSClient) lookupRecord(target string, qtype uint16) ([]string, bool) {
	m := new(dns.Msg)
	m.SetQuestion(target, qtype)
	m.RecursionDesired = true

	// Set DNSSEC OK bit for DNSSEC-related queries
	if qtype == dns.TypeDNSKEY || qtype == dns.TypeDS || qtype == dns.TypeRRSIG {
		m.SetEdns0(4096, true)
	}

	slog.Info("querying DNS server", "target", target, "qtype", qtype, "server", c.servers[c.currentServerIdx])
	for i := 0; i < len(c.servers); i++ {
		serverIdx := (c.currentServerIdx + i) % len(c.servers)
		server := c.servers[serverIdx]
		slog.Debug("trying DNS server", "target", target, "qtype", qtype, "server", server)

		r, _, err := c.client.Exchange(m, server)
		if err != nil {
			slog.Info("exchange error", "target", target, "qtype", qtype, "server", server, "error", err)
			continue
		}

		if r.Rcode != dns.RcodeSuccess {
			slog.Info("rcode error", "target", target, "qtype", qtype, "server", server, "rcode", r.Rcode)
			continue
		}
		c.currentServerIdx = (serverIdx + 1) % len(c.servers)

		var result []string
		for _, a := range r.Answer {
			h := a.Header()
			slog.Info("record type", "type", h.Rrtype, "qtype", qtype, "server", server)
			if h.Rrtype == dns.TypeRRSIG || h.Rrtype == qtype {
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
					result = append(result, fmt.Sprintf("%s %d %d %d", x.Target, x.Port, x.Weight, x.Priority))
				case *dns.CAA:
					result = append(result, fmt.Sprintf("%s %d %s", x.Value, x.Flag, x.Tag))
				case *dns.DNSKEY:
					result = append(result, fmt.Sprintf("%s %d %d %d", x.PublicKey, x.Flags, x.Protocol, x.Algorithm))
				case *dns.DS:
					result = append(result, fmt.Sprintf("%d %d %d %s", x.KeyTag, x.Algorithm, x.DigestType, x.Digest))
				//case *dns.RRSIG:
				//result = append(result, fmt.Sprintf("%d %d %d %d %s", x.TypeCovered, x.Algorithm, x.Labels, x.OrigTtl, x.Signature))
				case *dns.RRSIG: // Correctly handle RRSIG records here
					result = append(result, fmt.Sprintf("%d %d %d %d %d %d %s %d %s",
						x.TypeCovered, x.Algorithm, x.Labels, x.OrigTtl,
						x.Expiration, x.Inception, x.SignerName, x.KeyTag, x.Signature))
				default:
					slog.Info("Unknown record type", "type", h.Rrtype, "qtype", qtype, "server", server)
				}
			}
		}
		return result, true
	}
	return nil, false
}

// GetParentZone returns the parent zone of the given domain.
func (c *DNSClient) GetParentZone(domain string) (string, error) {
	// example.com. -> com.
	parent := dns.Fqdn(domain)
	labels := dns.SplitDomainName(parent)
	if len(labels) < 2 {
		return "", fmt.Errorf("invalid domain: %s", domain)
	}
	fqdn := strings.Join(labels[1:], ".") + "." // + "." for FQDN
	slog.Info("parent zone", "parent", parent, "fqdn", fqdn)
	return fqdn, nil
}

// validateRRSIG validates an RRSIG record against a DNSKEY.
func (c *DNSClient) validateRRSIG(domain string, dnskey *dns.DNSKEY, rrsig *dns.RRSIG) bool {
	// Construct a dummy DNSKEY RR from the DNSKEYResult
	keyRR := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    rrsig.OrigTtl,
		},
		Flags:     dnskey.Flags,
		Protocol:  dnskey.Protocol,
		Algorithm: dnskey.Algorithm,
		PublicKey: dnskey.PublicKey,
	}

	// Create a slice containing only the DNSKEY record
	rrSet := []dns.RR{keyRR}

	// miekg/dns has a built-in function for this
	err := rrsig.Verify(keyRR, rrSet)
	if err != nil {
		return false
	}
	return true
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
	DS     []string
	RRSIG  []string
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
		parser  func(string, string) (interface{}, error)
	}{
		{"A", result.A, func(domain, record string) (interface{}, error) {
			return ParseA(domain, record)
		}},
		{"AAAA", result.AAAA, func(domain, record string) (interface{}, error) {
			return ParseAAAA(domain, record)
		}},
		{"CNAME", result.CNAME, func(domain, record string) (interface{}, error) {
			return ParseCNAME(domain, record)
		}},
		{"TXT", result.TXT, func(domain, record string) (interface{}, error) {
			return ParseTXT(domain, record)
		}},
		{"NS", result.NS, func(domain, record string) (interface{}, error) {
			return ParseNS(domain, record)
		}},
		{"MX", result.MX, func(domain, record string) (interface{}, error) {
			return ParseMX(domain, record)
		}},
		{"SOA", result.SOA, func(domain, record string) (interface{}, error) {
			return ParseSOARecord(domain, record)
		}},
		{"PTR", result.PTR, func(domain, record string) (interface{}, error) {
			return ParsePTR(domain, record)
		}},
		{"CAA", result.CAA, func(domain, record string) (interface{}, error) {
			return ParseCAA(domain, record)
		}},
		{"DNSKEY", result.DNSKEY, func(domain, record string) (interface{}, error) {
			return ParseDNSKEY(domain, record)
		}},
		{"DS", result.DS, func(domain, record string) (interface{}, error) {
			return ParseDS(domain, record)
		}},
		{"RRSIG", result.RRSIG, func(domain, record string) (interface{}, error) {
			return ParseRRSIG(domain, record)
		}},
		{"SRV", result.SRV, func(domain, record string) (interface{}, error) {
			return ParseSRV(domain, record)
		}},
	}
	for _, r := range records {
		for _, entry := range r.entries {
			parsed, err := r.parser(result.Name, entry) // Pass the domain here
			if err != nil {
				fmt.Printf("Error parsing %s record for %s: %v\n", r.name, result.Name, err)
				continue
			}
			fmt.Printf("%s record for %s: %+v\n", r.name, result.Name, parsed)
		}
	}
	return nil
}

type ARecord struct {
	Domain string
	IP     string
}

func ParseA(domain, record string) (*ARecord, error) {
	return &ARecord{Domain: domain, IP: record}, nil
}

type AAAARecord struct {
	Domain string
	IP     string
}

func ParseAAAA(domain, record string) (*AAAARecord, error) {
	return &AAAARecord{Domain: domain, IP: record}, nil
}

type CNAMERecord struct {
	Domain string
	Target string
}

func ParseCNAME(domain, record string) (*CNAMERecord, error) {
	return &CNAMERecord{Domain: domain, Target: record}, nil
}

type MXRecord struct {
	Domain     string
	Preference uint16
	Target     string
}

func ParseMX(domain, record string) (*MXRecord, error) {
	parts := strings.Fields(record)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid MX record format")
	}
	pref, _ := strconv.ParseUint(parts[0], 10, 16)
	return &MXRecord{
		Domain:     domain,
		Preference: uint16(pref),
		Target:     parts[1],
	}, nil
}

type TXTRecord struct {
	Domain  string
	Content string
}

func ParseTXT(domain, record string) (*TXTRecord, error) {
	return &TXTRecord{Domain: domain, Content: record}, nil
}

type NSRecord struct {
	Domain     string
	NameServer string
}

func ParseNS(domain, record string) (*NSRecord, error) {
	return &NSRecord{Domain: domain, NameServer: record}, nil
}

type PTRRecord struct {
	Domain string
	Target string
}

func ParsePTR(domain, record string) (*PTRRecord, error) {
	return &PTRRecord{Domain: domain, Target: record}, nil
}

type CAAResult struct {
	Domain      string
	Value       string
	Flag        uint8
	Tag         string
	IsValid     bool
	ErrorReason string
}

func ParseCAA(domain, record string) (*CAAResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid CAA record format")
	}

	flag, _ := strconv.ParseUint(parts[1], 10, 8)

	return &CAAResult{
		Domain:  domain,
		Value:   parts[0],
		Flag:    uint8(flag),
		Tag:     parts[2],
		IsValid: true,
	}, nil
}

type DNSKEYResult struct {
	Domain      string
	PublicKey   string
	Flags       uint16
	Protocol    uint8
	Algorithm   uint8
	IsValid     bool
	ErrorReason string
}

func ParseDNSKEY(domain, record string) (*DNSKEYResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid DNSKEY record format")
	}

	flags, _ := strconv.ParseUint(parts[1], 10, 16)
	protocol, _ := strconv.ParseUint(parts[2], 10, 8)
	algorithm, _ := strconv.ParseUint(parts[3], 10, 8)

	return &DNSKEYResult{
		Domain:    domain,
		PublicKey: parts[0],
		Flags:     uint16(flags),
		Protocol:  uint8(protocol),
		Algorithm: uint8(algorithm),
		IsValid:   true,
	}, nil
}

type DSResult struct {
	Domain      string
	KeyTag      uint16
	Algorithm   uint8
	DigestType  uint8
	Digest      string
	IsValid     bool
	ErrorReason string
}

func ParseDS(domain, record string) (*DSResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid DS record format")
	}

	keyTag, _ := strconv.ParseUint(parts[0], 10, 16)
	algorithm, _ := strconv.ParseUint(parts[1], 10, 8)
	digestType, _ := strconv.ParseUint(parts[2], 10, 8)

	return &DSResult{
		Domain:     domain,
		KeyTag:     uint16(keyTag),
		Algorithm:  uint8(algorithm),
		DigestType: uint8(digestType),
		Digest:     parts[3],
		IsValid:    true,
	}, nil
}

type RRSIGResult struct {
	Domain      string
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OriginalTTL uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string
	Signature   string
	IsValid     bool
}

func ParseRRSIG(domain, record string) (*RRSIGResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 9 {
		return nil, fmt.Errorf("invalid RRSIG record format")
	}

	typeCovered, _ := strconv.ParseUint(parts[0], 10, 16)
	algorithm, _ := strconv.ParseUint(parts[1], 10, 8)
	labels, _ := strconv.ParseUint(parts[2], 10, 8)
	originalTTL, _ := strconv.ParseUint(parts[3], 10, 32)
	expiration, _ := strconv.ParseUint(parts[4], 10, 32)
	inception, _ := strconv.ParseUint(parts[5], 10, 32)
	keyTag, _ := strconv.ParseUint(parts[6], 10, 16)

	return &RRSIGResult{
		Domain:      domain,
		TypeCovered: uint16(typeCovered),
		Algorithm:   uint8(algorithm),
		Labels:      uint8(labels),
		OriginalTTL: uint32(originalTTL),
		Expiration:  uint32(expiration),
		Inception:   uint32(inception),
		KeyTag:      uint16(keyTag),
		SignerName:  parts[7],
		Signature:   parts[8],
		IsValid:     true,
	}, nil
}

type SRVResult struct {
	Domain      string
	Target      string
	Port        uint16
	Weight      uint16
	Priority    uint16
	IsValid     bool
	ErrorReason string
}

func ParseSRV(domain, record string) (*SRVResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid SRV record format")
	}

	port, _ := strconv.ParseUint(parts[1], 10, 16)
	weight, _ := strconv.ParseUint(parts[2], 10, 16)
	priority, _ := strconv.ParseUint(parts[3], 10, 16)

	return &SRVResult{
		Domain:   domain,
		Target:   parts[0],
		Port:     uint16(port),
		Weight:   uint16(weight),
		Priority: uint16(priority),
		IsValid:  true,
	}, nil
}

type SOAResult struct {
	Domain      string
	NameServer  string
	AdminEmail  string
	Serial      uint32
	Refresh     uint32
	Retry       uint32
	Expire      uint32
	MinimumTTL  uint32
	IsValid     bool
	ErrorReason string
}

// ParseSOARecord parses a SOA record string into a SOAResult struct.
//
// The SOA records arrive as a slice of strings, with each string
// representing a field in the SOA record.
func ParseSOARecord(domain, record string) (*SOAResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 7 {
		return nil, fmt.Errorf("invalid SOA record format")
	}

	serial, _ := strconv.ParseUint(parts[2], 10, 32)
	refresh, _ := strconv.ParseUint(parts[3], 10, 32)
	retry, _ := strconv.ParseUint(parts[4], 10, 32)
	expire, _ := strconv.ParseUint(parts[5], 10, 32)
	minTTL, _ := strconv.ParseUint(parts[6], 10, 32)

	return &SOAResult{
		Domain:     domain,
		NameServer: parts[0],
		AdminEmail: parts[1],
		Serial:     uint32(serial),
		Refresh:    uint32(refresh),
		Retry:      uint32(retry),
		Expire:     uint32(expire),
		MinimumTTL: uint32(minTTL),
		IsValid:    true,
	}, nil
}
