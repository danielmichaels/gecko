package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/danielmichaels/doublestag/internal/config"
	"github.com/danielmichaels/doublestag/internal/logging"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// RCodeToString is a map that translates DNS response codes to their string representations.
// It maps integer DNS response codes to their corresponding string values.
var RCodeToString = map[int]string{
	dns.RcodeSuccess:        "NOERROR",
	dns.RcodeFormatError:    "FORMERR",
	dns.RcodeServerFailure:  "SERVFAIL",
	dns.RcodeNameError:      "NXDOMAIN",
	dns.RcodeNotImplemented: "NOTIMP",
	dns.RcodeRefused:        "REFUSED",
}

// QTypeToString is a map that maps DNS record types (uint16) to their string representations.
// It provides a convenient way to convert numeric record types to their human-readable names.
var QTypeToString = map[uint16]string{
	dns.TypeA:      "A",
	dns.TypeNS:     "NS",
	dns.TypeCNAME:  "CNAME",
	dns.TypeSOA:    "SOA",
	dns.TypePTR:    "PTR",
	dns.TypeMX:     "MX",
	dns.TypeTXT:    "TXT",
	dns.TypeAAAA:   "AAAA",
	dns.TypeSRV:    "SRV",
	dns.TypeCAA:    "CAA",
	dns.TypeDNSKEY: "DNSKEY",
	dns.TypeDS:     "DS",
	dns.TypeRRSIG:  "RRSIG",
}

// DNSClient is a struct that holds the DNS client, logger, and a list of DNS servers to use for lookups.
// It provides methods to perform various DNS record lookups, such as CNAME, A, and AAAA.
type DNSClient struct {
	// client is a DNS client used for making DNS queries.
	client *dns.Client
	// logger is a logger instance used by the DNSClient for logging purposes.
	logger *slog.Logger
	// servers is a slice of DNS server addresses to be used for DNS lookups.
	// If no custom servers are configured, it defaults to a single entry, "8.8.8.8:53" (Google's public DNS server).
	servers []string
	// currentServerIdx is the index of the current DNS server being used for lookups.
	// It is used to keep track of the server being used and cycle through the list of configured servers.
	currentServerIdx int
	// conf is a pointer to the application configuration struct.
	// It is used to access the configuration settings for the DNS client.
	conf *config.Conf
}

// NewDNSClient creates a new DNSClient instance with the configured DNS servers and a logger.
// It initializes the DNS client and sets the current server index to 0.
func NewDNSClient() *DNSClient {
	cfg := config.AppConfig()
	logger, _ := logging.SetupLogger("dns-client", cfg)
	return &DNSClient{
		servers:          getDNSServers(),
		client:           new(dns.Client),
		currentServerIdx: 0,
		logger:           logger,
		conf:             cfg,
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

// numRetries returns the number of retries to use for DNS lookups. If the configured
// DNSMaxRetries is 0, it defaults to 5 retries.
func (c *DNSClient) numRetries() int {
	numRetries := c.conf.AppConf.DNSMaxRetries
	if numRetries == 0 {
		numRetries = 5
	}
	return numRetries
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
	return c.lookupRecord(target, dns.TypeDS)
}

// lookupRecord performs a DNS lookup for the given target and query type, using the specified DNS server.
// It returns the results as a slice of strings, and a boolean indicating whether the lookup was successful.
func (c *DNSClient) lookupRecord(target string, qtype uint16) ([]string, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(target), qtype)
	m.RecursionDesired = true

	// Set DNSSEC OK bit for DNSSEC-related queries
	if qtype == dns.TypeDNSKEY || qtype == dns.TypeDS || qtype == dns.TypeRRSIG {
		m.SetEdns0(4096, true)
	}

	c.logger.Debug(
		"querying DNS server",
		"target",
		target,
		"qtype",
		QTypeToString[qtype],
		"server",
		c.servers[c.currentServerIdx],
	)

	numRetries := c.numRetries()
	for attempt := 0; attempt < numRetries; attempt++ {
		// Randomly select a server for this attempt
		serverIdx := rand.Intn(len(c.servers))
		server := c.servers[serverIdx]

		r, _, err := c.client.Exchange(m, server)
		if err != nil {
			c.logger.Debug(
				"exchange error",
				"target",
				target,
				"qtype",
				QTypeToString[qtype],
				"server",
				server,
				"error",
				err,
			)
			c.backoffSleep(attempt)
			continue
		}
		// exit early on NXDOMAIN
		if r.Rcode == dns.RcodeNameError {
			c.logger.Debug(
				"rcode NXDOMAIN",
				"target", target,
				"qtype", QTypeToString[qtype],
				"server", server,
				"rcode", RCodeToString[r.Rcode],
			)
			return nil, false // Return immediately
		}
		if r.Rcode != dns.RcodeSuccess {
			c.logger.Debug(
				"rcode error",
				"target",
				target,
				"qtype",
				QTypeToString[qtype],
				"server",
				server,
				"rcode",
				RCodeToString[r.Rcode],
			)
			c.backoffSleep(attempt)
			continue
		}
		return processResponse(r, qtype), true
	}
	return nil, false
}
func processResponse(r *dns.Msg, qtype uint16) []string {
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
				result = append(result, fmt.Sprintf("%s %s %d %d %d %d %d", x.Ns, x.Mbox, x.Serial, x.Refresh, x.Retry, x.Expire, x.Minttl))
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
			case *dns.RRSIG:
				result = append(result, fmt.Sprintf("%d %d %d %d %d %d %s %d %s", x.TypeCovered, x.Algorithm, x.Labels, x.OrigTtl, x.Expiration, x.Inception, x.SignerName, x.KeyTag, x.Signature))
			}
		}
	}
	return result
}

// GetParentZone returns the parent zone of the given domain.
func (c *DNSClient) GetParentZone(domain string) (string, error) {
	// Handle root zone case
	if domain == "." {
		return "", nil
	}
	labels := dns.SplitDomainName(domain)
	if len(labels) < 2 {
		// If we only have one label, we're at the top level (e.g., "au.").
		// Return an empty string to signal that there's no parent.
		// return "", fmt.Errorf("invalid domain: %s", domain)
		return ".", nil
	}
	fqdn := strings.Join(labels[1:], ".") + "."
	return fqdn, nil
}

// LookupDNSKEYWithRRSIG performs a DNS query for the DNSKEY and RRSIG records
// for the given target domain. It returns the DNSKEY and RRSIG records, or
// false if the query was unsuccessful.
func (c *DNSClient) LookupDNSKEYWithRRSIG(target string) ([]string, []string, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(target), dns.TypeDNSKEY)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

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

		var dnskeys []string
		var rrsigs []string

		for _, a := range r.Answer {
			switch x := a.(type) {
			case *dns.DNSKEY:
				dnskeys = append(dnskeys, fmt.Sprintf("%s %d %d %d",
					x.PublicKey, x.Flags, x.Protocol, x.Algorithm))
			case *dns.RRSIG:
				rrsigs = append(rrsigs, fmt.Sprintf("%d %d %d %d %d %d %s %d %s",
					x.TypeCovered, x.Algorithm, x.Labels, x.OrigTtl,
					x.Expiration, x.Inception, x.SignerName, x.KeyTag, x.Signature))
			}
		}
		return dnskeys, rrsigs, true
	}
	return nil, nil, false
}

// sendDNSSECQuery sends a DNS query and returns the response message and a
// boolean indicating whether the query was successful. It tries each of the
// configured DNS servers in a round-robin fashion until a successful response
// is received or all servers have been tried.
func (c *DNSClient) sendDNSSECQuery(m *dns.Msg) (*dns.Msg, bool) {
	numRetries := c.numRetries()
	for attempt := 0; attempt < numRetries; attempt++ {
		serverIdx := rand.Intn(len(c.servers))
		server := c.servers[serverIdx]

		r, _, err := c.client.Exchange(m, server)
		if err != nil || r.Rcode != dns.RcodeSuccess {
			c.backoffSleep(attempt)
			continue
		}
		return r, true
	}
	return nil, false
}

// isZoneApex checks if the given domain is the zone apex by querying for the SOA record.
// It returns true if the domain is the zone apex, false otherwise.
func (c *DNSClient) isZoneApex(domain string) bool {
	// Query for SOA record to determine if this is a zone apex
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)

	client := NewDNSClient()
	response, ok := client.sendDNSSECQuery(m)

	return ok && len(response.Answer) > 0
}

// validateRRSIG validates an RRSIG record against a DNSKEY and a record set.
func (c *DNSClient) validateRRSIG(rrSet []dns.RR, dnskey *dns.DNSKEY, rrsig *dns.RRSIG) bool {
	err := rrsig.Verify(dnskey, rrSet)
	return err == nil
}

// ValidateDNSSEC performs the complete DNSSEC validation for a given domain.
func (c *DNSClient) ValidateDNSSEC(domain string) error {
	return c.validateDNSSECRecursive(domain, dns.Fqdn(domain)) // Start recursive validation.
}

// validateDNSSECRecursive is the recursive helper function for ValidateDNSSEC.
func (c *DNSClient) validateDNSSECRecursive(originalDomain, currentDomain string) error {
	// 1. Query for DNSKEY and RRSIG records at the current zone.
	dnskeyRRs, rrsigRRs, ok := c.LookupDNSKEYWithRRSIG(currentDomain)
	// end validation early for non-DNSSEC enabled domain, here we don't
	// attempt any further validation
	if !ok || len(dnskeyRRs) == 0 || len(rrsigRRs) == 0 {
		return errors.New(DNSSECNotImplemented)
	}

	var dnskeys []*dns.DNSKEY
	for _, key := range dnskeyRRs {
		parsedKey, err := ParseDNSKEY(currentDomain, key)
		if err != nil {
			return fmt.Errorf("error parsing DNSKEY: %w", err)
		}
		c.logger.Debug(
			"Parsed DNSKEY",
			"currentDomain",
			currentDomain,
			"parsedKey",
			parsedKey,
		) // Log the parsed key
		if parsedKey != nil {
			dnskeys = append(dnskeys, &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(currentDomain),
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Flags:     parsedKey.Flags,
				Protocol:  parsedKey.Protocol,
				Algorithm: parsedKey.Algorithm,
				PublicKey: parsedKey.PublicKey,
			})
		}
	}

	// Parse RRSIG records
	var rrsigs []*dns.RRSIG
	for _, record := range rrsigRRs {
		rrsigResult, err := ParseRRSIG(currentDomain, record)
		if err != nil {
			return fmt.Errorf("error parsing RRSIG: %w", err)
		}
		c.logger.Debug(
			"Parsed RRSIG",
			"currentDomain",
			currentDomain,
			"rrsigResult",
			rrsigResult,
		) // Log the parsed RRSIG
		// Convert *RRSIGResult to dns.RRSIG.
		rrsig := dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(currentDomain),
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    rrsigResult.OriginalTTL,
			},
			TypeCovered: rrsigResult.TypeCovered,
			Algorithm:   rrsigResult.Algorithm,
			Labels:      rrsigResult.Labels,
			OrigTtl:     rrsigResult.OriginalTTL,
			Expiration:  rrsigResult.Expiration,
			Inception:   rrsigResult.Inception,
			KeyTag:      rrsigResult.KeyTag,
			SignerName:  rrsigResult.SignerName,
			Signature:   rrsigResult.Signature,
		}
		rrsigs = append(rrsigs, &rrsig)
	}
	// 2.  Retrieve the records we want to validate (in this case, we are validating the DNSKEY records themselves at the zone apex)
	rrSet := make([]dns.RR, 0, len(dnskeys))
	for _, k := range dnskeys {
		c.logger.Debug("Adding DNSKEY to rrSet", "dnskey", k) // Log each DNSKEY added to rrSet
		rrSet = append(rrSet, k)
	}

	// 3. Verify RRSIG.
	validated := false
	for _, rrsig := range rrsigs {
		if rrsig.TypeCovered != dns.TypeDNSKEY {
			c.logger.Debug("Skipping RRSIG - not covering DNSKEY", "rrsig", rrsig)
			continue // We're validating the DNSKEY record set.
		}
		for _, dnskey := range dnskeys {
			if c.validateRRSIG(rrSet, dnskey, rrsig) {
				validated = true
				c.logger.Debug("RRSIG validated successfully!", "rrsig", rrsig, "dnskey", dnskey)
				break // One valid signature is enough.
			} else {
				c.logger.Debug("RRSIG validation failed", "rrsig", rrsig, "dnskey", dnskey)
			}
		}
		if validated {
			break
		}
	}
	if !validated {
		return errors.New(DNSSECFailedZoneApexValidation)
	}

	// 4. Establish Chain of Trust.
	// Separate KSKs and ZSKs.
	var ksks []*dns.DNSKEY
	for _, key := range dnskeys {
		if key.Flags == 257 {
			ksks = append(ksks, key)
		}
	}

	if len(ksks) > 0 { // Only if KSKs exist, try to validate DS records.
		parentZone, err := c.GetParentZone(currentDomain)
		if err != nil {
			return fmt.Errorf("getting parent zone: %w", err)
		}

		dsRecords, ok := c.LookupDS(currentDomain) // LookupDS now queries the parent.
		// dsRecords, ok := c.LookupDS(parentZone) // LookupDS now queries the parent.
		if !ok {
			// If we are at the root, we don't expect DS records
			if currentDomain == "." {
				return nil
			}
			return errors.New(DNSSECNotImplemented)
		}

		// Parse DS records.
		var dsSet []*dns.DS
		for _, dsRecord := range dsRecords {
			c.logger.Debug(
				"Found DS record (check zone/domain)",
				"dnskey",
				dsRecord,
				"parentZone",
				parentZone,
				"currentDomain",
				currentDomain,
			)
			// ds, err := ParseDS(parentZone, dsRecord)
			ds, err := ParseDS(currentDomain, dsRecord)
			if err != nil {
				c.logger.Warn("Error parsing DS record", "error", err)
				continue // Skip invalid DS records.
			}
			// ds.Domain = parentZone
			dsSet = append(dsSet, &dns.DS{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(currentDomain),
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
				},
				KeyTag:     ds.KeyTag,
				Algorithm:  ds.Algorithm,
				DigestType: ds.DigestType,
				Digest:     ds.Digest,
			})

		}
		if len(dsSet) == 0 && currentDomain != "." {
			c.logger.Error(
				"dsSet and currentDomain err",
				"dsSet",
				dsSet,
				"currentDomain",
				currentDomain,
			)
			return errors.New(DNSSECFailedChainOfTrust)
		}

		// Verify DS against DNSKEY hash.
		dsValid := false
		for _, ksk := range ksks {
			for _, ds := range dsSet {
				generatedDS, err := c.generateDS(
					dns.Fqdn(currentDomain),
					ksk,
					ds.DigestType,
				)
				if err != nil {
					continue
				}
				if c.compareDS(ds, generatedDS) {
					dsValid = true
					break // One valid DS is enough.
				}
			}
			if dsValid {
				break
			}
		}
		if !dsValid && currentDomain != "." {
			c.logger.Error(
				"ds invalid",
				"dsSet",
				dsSet,
				"parentZone",
				parentZone,
				"currentDomain",
				currentDomain,
			)
			return errors.New(DNSSECFailedChainOfTrust)
		}

		// 5. Repeat for higher zones (recursively).
		if parentZone != "." {
			if err := c.validateDNSSECRecursive(originalDomain, parentZone); err != nil {
				return err
			}
		}
	}

	return nil
}

// generateDS creates a DS record from a DNSKEY using specified digest type
func (c *DNSClient) generateDS(
	name string,
	key *dns.DNSKEY,
	digestType uint8,
) (*dns.DS, error) {
	originalAlgorithm := key.Algorithm
	ds := key.ToDS(digestType)
	if ds == nil {
		return nil, fmt.Errorf("failed to generate DS record")
	}

	ds.Algorithm = originalAlgorithm
	ds.Hdr.Name = dns.Fqdn(name)
	c.logger.Debug("generated DS record",
		"name", name,
		"keytag", ds.KeyTag,
		"algorithm", ds.Algorithm,
		"digest_type", ds.DigestType,
		"digest", ds.Digest)
	return ds, nil
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

// EnumerateWithSubfinderCallback enumerates subdomains for the given domain using the Subfinder tool,
// and calls the provided callback function for each resolved host entry.
// The concurrency parameter specifies the number of concurrent requests to make.
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
	Target     string
	Preference uint16
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
	Tag         string
	ErrorReason string
	Flag        uint8
	IsValid     bool
}

func ParseCAA(domain, record string) (*CAAResult, error) {
	parts := strings.Fields(record)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid CAA record format")
	}

	flag, _ := strconv.ParseUint(parts[1], 10, 8)
	value := parts[0]
	if len(parts) > 3 {
		value = strings.Join(parts[3:], " ")
	}

	return &CAAResult{
		Domain:  domain,
		Value:   value,
		Flag:    uint8(flag),
		Tag:     parts[2],
		IsValid: true,
	}, nil
}

type DNSKEYResult struct {
	Domain      string
	PublicKey   string
	ErrorReason string
	Flags       uint16
	Protocol    uint8
	Algorithm   uint8
	IsValid     bool
}

func ParseDNSKEY(domain, record string) (*DNSKEYResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid DNSKEY record format")
	}

	flags, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid Flags: %w", err)
	}
	protocol, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid Protocol: %w", err)
	}
	algorithm, err := strconv.ParseUint(parts[3], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid Algorithm: %w", err)
	}
	result := &DNSKEYResult{
		Domain:    domain,
		PublicKey: parts[0],
		Flags:     uint16(flags),
		Protocol:  uint8(protocol),
		Algorithm: uint8(algorithm),
		IsValid:   true,
	}
	return result, nil
}

type DSResult struct {
	Domain      string
	Digest      string
	ErrorReason string
	KeyTag      uint16
	Algorithm   uint8
	DigestType  uint8
	IsValid     bool
}

func ParseDS(domain, record string) (*DSResult, error) {
	parts := strings.Fields(record)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid DS record format")
	}

	keyTag, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid KeyTag: %w", err)
	}
	algorithm, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid Algorithm: %w", err)
	}
	digestType, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid DigestType: %w", err)
	}

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
	SignerName  string
	Signature   string
	OriginalTTL uint32
	Expiration  uint32
	Inception   uint32
	TypeCovered uint16
	KeyTag      uint16
	Algorithm   uint8
	Labels      uint8
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
	signerName := parts[6]
	keyTag, _ := strconv.ParseUint(parts[7], 10, 16)

	result := &RRSIGResult{
		Domain:      domain,
		TypeCovered: uint16(typeCovered),
		Algorithm:   uint8(algorithm),
		Labels:      uint8(labels),
		OriginalTTL: uint32(originalTTL),
		Expiration:  uint32(expiration),
		Inception:   uint32(inception),
		KeyTag:      uint16(keyTag),
		SignerName:  signerName,
		Signature:   parts[8],
		IsValid:     true,
	}
	return result, nil
}

type SRVResult struct {
	Domain      string
	Target      string
	ErrorReason string
	Port        uint16
	Weight      uint16
	Priority    uint16
	IsValid     bool
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
	ErrorReason string
	Serial      uint32
	Refresh     uint32
	Retry       uint32
	Expire      uint32
	MinimumTTL  uint32
	IsValid     bool
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

func (c *DNSClient) AttemptZoneTransfer(domain string) *ZoneTransferResult {
	fqdn := dns.Fqdn(domain)
	result := NewZoneTransferResult(domain)

	nameservers, ok := c.LookupNS(fqdn)
	if !ok || len(nameservers) == 0 {
		result.Error = "no nameservers found"
		return result
	}
	result.NS = nameservers

	for _, ns := range nameservers {
		nsAddr := ns + ":53"

		isVulnerable := false

		if records := c.attemptAXFR(fqdn, nsAddr); len(records) > 0 {
			result.AXFR[nsAddr] = records
			isVulnerable = true
			result.SuccessfulTransfers[nsAddr] = "AXFR"
		}

		if records := c.attemptIXFR(fqdn, nsAddr); len(records) > 0 {
			result.IXFR[nsAddr] = records
			isVulnerable = true
			result.SuccessfulTransfers[nsAddr] = "IXFR"
		}
		if isVulnerable {
			result.Vulnerable = true
			result.VulnerableNameservers = append(result.VulnerableNameservers, nsAddr)
		}
	}

	return result
}

func (c *DNSClient) attemptAXFR(domain, nameserver string) []dns.RR {
	m := new(dns.Msg)
	m.SetAxfr(domain)

	return c.performTransfer(domain, nameserver, m)
}

func (c *DNSClient) attemptIXFR(domain, nameserver string) []dns.RR {
	// Get SOA first to get serial number
	soa, ok := c.LookupSOA(domain)
	if !ok || len(soa) == 0 {
		return nil
	}

	// Parse SOA to get serial
	soaResult, err := ParseSOARecord(domain, soa[0])
	if err != nil {
		return nil
	}

	m := new(dns.Msg)
	m.SetIxfr(domain, soaResult.Serial, soaResult.NameServer, soaResult.AdminEmail)

	return c.performTransfer(domain, nameserver, m)
}

func (c *DNSClient) performTransfer(domain, nameserver string, m *dns.Msg) []dns.RR {
	transfer := &dns.Transfer{
		DialTimeout: time.Second * 10,
		ReadTimeout: time.Second * 10,
	}

	transferType := "AXFR"
	if m.Question[0].Qtype == dns.TypeIXFR {
		transferType = "IXFR"
	}
	c.logger.Debug("attempting zone transfer",
		"domain", domain,
		"nameserver", nameserver,
		"type", transferType,
	)

	env, err := transfer.In(m, nameserver)
	if err != nil {
		c.logger.Debug("zone transfer failed",
			"domain", domain,
			"nameserver", nameserver,
			"type", transferType,
			"error", err)
		return nil
	}

	var records []dns.RR
	for e := range env {
		if e.Error != nil {
			continue
		}
		records = append(records, e.RR...)
	}
	if len(records) > 0 {
		c.logger.Debug("zone transfer successful",
			"domain", domain,
			"nameserver", nameserver,
			"type", transferType,
			"records", len(records))
	}
	return records
}

// backoffSleep implements a simple exponential backoff sleep.
func (c *DNSClient) backoffSleep(attempt int) {
	cfg := config.AppConfig()

	baseDelay := time.Duration(cfg.AppConf.DNSBackoffBaseDelay) * time.Second
	if baseDelay == 0 {
		baseDelay = 1 * time.Second // Default base delay
	}
	maxDelay := time.Duration(cfg.AppConf.DNSBackoffMaxDelay) * time.Second
	if maxDelay == 0 {
		maxDelay = 16 * time.Second // Default maximum delay
	}

	delay := baseDelay * time.Duration(1<<uint(attempt))

	if delay > maxDelay {
		delay = maxDelay
	}

	c.logger.Debug("backoff sleep", "delay", delay)
	time.Sleep(delay)
}
