package scanner

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/danielmichaels/doublestag/internal/config"
	"github.com/danielmichaels/doublestag/internal/logging"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"hash"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type DNSClient struct {
	client           *dns.Client
	servers          []string
	currentServerIdx int
	logger           *slog.Logger
}

func NewDNSClient() *DNSClient {
	cfg := config.AppConfig()
	logger, _ := logging.SetupLogger("dns-client", cfg)
	return &DNSClient{
		servers:          getDNSServers(),
		client:           new(dns.Client),
		currentServerIdx: 0,
		logger:           logger,
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

	c.logger.Debug("querying DNS server", "target", target, "qtype", qtype, "server", c.servers[c.currentServerIdx])
	for i := 0; i < len(c.servers); i++ {
		serverIdx := (c.currentServerIdx + i) % len(c.servers)
		server := c.servers[serverIdx]

		r, _, err := c.client.Exchange(m, server)
		if err != nil {
			c.logger.Debug("exchange error", "target", target, "qtype", qtype, "server", server, "error", err)
			continue
		}

		if r.Rcode != dns.RcodeSuccess {
			c.logger.Debug("rcode error", "target", target, "qtype", qtype, "server", server, "rcode", r.Rcode)
			continue
		}
		c.currentServerIdx = (serverIdx + 1) % len(c.servers)

		var result []string
		for _, a := range r.Answer {
			h := a.Header()
			c.logger.Debug("record type", "type", h.Rrtype, "qtype", qtype, "server", server)
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
					result = append(result, fmt.Sprintf("%s %d %d %d", x.Target, x.Port, x.Weight, x.Priority))
				case *dns.CAA:
					result = append(result, fmt.Sprintf("%s %d %s", x.Value, x.Flag, x.Tag))
				case *dns.DNSKEY:
					result = append(result, fmt.Sprintf("%s %d %d %d", x.PublicKey, x.Flags, x.Protocol, x.Algorithm))
				case *dns.DS:
					result = append(result, fmt.Sprintf("%d %d %d %s", x.KeyTag, x.Algorithm, x.DigestType, x.Digest))
				case *dns.RRSIG: // Correctly handle RRSIG records here
					result = append(result, fmt.Sprintf("%d %d %d %d %d %d %s %d %s",
						x.TypeCovered, x.Algorithm, x.Labels, x.OrigTtl,
						x.Expiration, x.Inception, x.SignerName, x.KeyTag, x.Signature))
				default:
					c.logger.Debug("Unknown record type", "type", h.Rrtype, "qtype", qtype, "server", server)
				}
			}
		}
		return result, true
	}
	return nil, false
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
		//return "", fmt.Errorf("invalid domain: %s", domain)
		return ".", nil
	}
	fqdn := strings.Join(labels[1:], ".") + "."
	return fqdn, nil
}

// validateDS validates DS records against KSKs (Key Signing Keys)
func (c *DNSClient) validateDS(domain string, ksks []DNSKEYResult) bool {
	dsRecords, ok := c.LookupDS(domain)
	if !ok || len(dsRecords) == 0 {
		return false
	}

	for _, dsRecord := range dsRecords {
		ds, err := ParseDS(domain, dsRecord)
		if err != nil {
			continue
		}

		// Convert DSResult to dns.DS
		dsRR := &dns.DS{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(domain),
				Rrtype: dns.TypeDS,
				Class:  dns.ClassINET,
			},
			KeyTag:     ds.KeyTag,
			Algorithm:  ds.Algorithm,
			DigestType: ds.DigestType,
			Digest:     ds.Digest,
		}

		for _, ksk := range ksks {
			dnskey := &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(domain),
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
				},
				Flags:     ksk.Flags,
				Protocol:  ksk.Protocol,
				Algorithm: ds.Algorithm,
				PublicKey: ksk.PublicKey,
			}

			generatedDS := dnskey.ToDS(ds.DigestType)
			if generatedDS == nil {
				continue
			}

			if c.compareDS(generatedDS, dsRR) {
				c.logger.Debug("DS record validated", "keytag", ds.KeyTag)
				return true
			}
		}
	}
	c.logger.Warn("DS validation failed", "domain", domain)
	return false
}

// calculateKeyDigest calculates the digest for a DNSKEY
func (c *DNSClient) calculateKeyDigest(key *dns.DNSKEY, digestType uint8) (string, error) {
	var h hash.Hash

	switch digestType {
	case dns.SHA1:
		h = sha1.New()
	case dns.SHA256:
		h = sha256.New()
	case dns.SHA384:
		h = sha512.New384()
	default:
		return "", fmt.Errorf("unsupported digest type: %d", digestType)
	}

	// Create canonical form of DNSKEY
	DNSBufferSize := 4096
	canonical := make([]byte, DNSBufferSize)
	key.Hdr.Name = dns.CanonicalName(key.Hdr.Name)
	offset, err := dns.PackRR(key, canonical, 0, nil, false)
	if err != nil {
		return "", err
	}
	slog.Debug("packed RR", "name", key.Hdr.Name, "offset", offset)

	h.Write(canonical[:offset])
	digest := hex.EncodeToString(h.Sum(nil))
	c.logger.Debug("calculateKeyDigest", "name", key.Hdr.Name, "digest", digest)
	return digest, nil
}
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

func (c *DNSClient) sendDNSSECQuery(m *dns.Msg) (*dns.Msg, bool) {
	for i := 0; i < len(c.servers); i++ {
		serverIdx := (c.currentServerIdx + i) % len(c.servers)
		server := c.servers[serverIdx]

		r, _, err := c.client.Exchange(m, server)
		if err != nil || r.Rcode != dns.RcodeSuccess {
			continue
		}

		c.currentServerIdx = (serverIdx + 1) % len(c.servers)
		return r, true
	}
	return nil, false
}

func (c *DNSClient) isZoneApex(domain string) bool {
	// Query for SOA record to determine if this is a zone apex
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)

	client := NewDNSClient()
	response, ok := client.sendDNSSECQuery(m)

	return ok && len(response.Answer) > 0
}

func (c *DNSClient) validateZoneApex(domain string, dnskeys []DNSKEYResult, rrsigs []dns.RRSIG) bool {
	if len(dnskeys) == 0 || len(rrsigs) == 0 {
		return false
	}

	// Iterate through RRSIGs, find the one covering DNSKEY, and validate it.
	for _, rrsig := range rrsigs {
		if rrsig.TypeCovered == dns.TypeDNSKEY {
			// Find the corresponding DNSKEY.
			for _, dnskey := range dnskeys {
				// Construct a *dns.DNSKEY from the DNSKEYResult
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

				if c.validateRRSIG([]dns.RR{keyRR}, keyRR, &rrsig) {
					return true
				}
			}
		}
	}
	return false
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
func (c *DNSClient) validateChainOfTrust(domain string, ksks []DNSKEYResult) bool {
	return c.validateDS(domain, ksks)
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
		c.logger.Debug("Parsed DNSKEY", "currentDomain", currentDomain, "parsedKey", parsedKey) // Log the parsed key
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
		c.logger.Debug("Parsed RRSIG", "currentDomain", currentDomain, "rrsigResult", rrsigResult) // Log the parsed RRSIG
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
		//dsRecords, ok := c.LookupDS(parentZone) // LookupDS now queries the parent.
		if !ok {
			//If we are at the root, we don't expect DS records
			if currentDomain == "." {
				return nil
			}
			return errors.New(DNSSECNotImplemented)
		}

		// Parse DS records.
		var dsSet []*dns.DS
		for _, dsRecord := range dsRecords {
			c.logger.Debug("Found DS record (check zone/domain)", "dnskey", dsRecord, "parentZone", parentZone, "currentDomain", currentDomain)
			//ds, err := ParseDS(parentZone, dsRecord)
			ds, err := ParseDS(currentDomain, dsRecord)
			if err != nil {
				c.logger.Warn("Error parsing DS record", "error", err)
				continue // Skip invalid DS records.
			}
			//ds.Domain = parentZone
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
			c.logger.Error("dsSet and currentDomain err", "dsSet", dsSet, "currentDomain", currentDomain)
			return errors.New(DNSSECFailedChainOfTrust)
		}

		// Verify DS against DNSKEY hash.
		dsValid := false
		for _, ksk := range ksks {
			for _, ds := range dsSet {
				generatedDS, err := c.generateDS(dns.Fqdn(currentDomain), ksk, ds.DigestType, ds.Algorithm)
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
			c.logger.Error("ds invalid", "dsSet", dsSet, "parentZone", parentZone, "currentDomain", currentDomain)
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
func (c *DNSClient) generateDS(name string, key *dns.DNSKEY, digestType, algorithm uint8) (*dns.DS, error) {
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
	signerName := parts[6]
	keyTag, _ := strconv.ParseUint(parts[7], 10, 16)

	return &RRSIGResult{
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
