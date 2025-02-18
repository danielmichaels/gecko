package scanner

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/miekg/dns"
	"hash"
	"log/slog"
	"strings"
)

const (
	DNSSECNotImplemented           = "DNSSEC not implemented"
	DNSSECFullyImplemented         = "DNSSEC fully implemented"
	DNSSECFailedChainOfTrust       = "DNSSEC failed chain of trust validation"
	DNSSECFailedZoneApexValidation = "DNSSEC failed zone apex validation"
	DNSSECNotApplicable            = "DNSSEC not applicable"
)

type DNSSECResult struct {
	Domain          string
	Status          string
	HasDNSKEY       bool
	HasDS           bool
	HasRRSIG        bool
	ValidationError string
	KSKs            []DNSKEYResult
	ZSKs            []DNSKEYResult
}

func ScanDNSSEC(domain string) *DNSSECResult {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	result := &DNSSECResult{
		Domain: domain,
	}

	client := NewDNSClient()

	// Check if domain is zone apex
	if !isZoneApex(domain) {
		result.Status = DNSSECNotApplicable
		return result
	}

	// Query for DNSKEY records with DNSSEC
	dnskeyRecords, rrsigRecords, ok := client.LookupDNSKEYWithRRSIG(dns.Fqdn(domain))
	if !ok {
		result.Status = DNSSECNotImplemented
		return result
	}

	// Parse DNSKEY records
	var dnskeys []DNSKEYResult
	var rrsigs []dns.RRSIG

	// Parse DNSKEY records
	for _, record := range dnskeyRecords {
		key, err := ParseDNSKEY(domain, record)
		if err != nil {
			slog.Error("ParseDNSKEY failed", "domain", domain, "err", err)
			continue
		}
		dnskeys = append(dnskeys, *key)
	}

	// Parse RRSIG records
	for _, record := range rrsigRecords {
		rrsigResult, err := ParseRRSIG(domain, record)
		if err != nil {
			slog.Error("Error parsing RRSIG record", "error", err)
			continue
		}
		// Convert *RRSIGResult to dns.RRSIG.  This is the fix.
		rrsig := dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(domain),
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    rrsigResult.OriginalTTL, // Use the parsed TTL
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
		rrsigs = append(rrsigs, rrsig)
	}

	if len(dnskeys) == 0 {
		result.Status = DNSSECNotImplemented
		return result
	}

	// Separate KSKs (flag 257) and ZSKs (flag 256)
	for _, key := range dnskeys {
		if key.Flags == 257 {
			result.KSKs = append(result.KSKs, key)
		} else if key.Flags == 256 {
			result.ZSKs = append(result.ZSKs, key)
		}
	}

	result.HasDNSKEY = len(dnskeys) > 0
	result.HasRRSIG = len(rrsigs) > 0

	// Validate zone apex signature
	zoneApexValid := validateZoneApex(domain, dnskeys, rrsigs)

	// Validate chain of trust (DS records)
	result.HasDS = checkDSExistence(domain) // Check for DS existence separately
	chainOfTrustValid := validateChainOfTrust(domain, result.KSKs)

	// Set final status based on validation results
	result.Status = determineDNSSECStatus(zoneApexValid, chainOfTrustValid)

	return result
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

func isZoneApex(domain string) bool {
	// Query for SOA record to determine if this is a zone apex
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)

	client := NewDNSClient()
	response, ok := client.sendDNSSECQuery(m)

	return ok && len(response.Answer) > 0
}

func validateZoneApex(domain string, dnskeys []DNSKEYResult, rrsigs []dns.RRSIG) bool {
	if len(dnskeys) == 0 || len(rrsigs) == 0 {
		return false
	}

	client := NewDNSClient()

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

				if client.validateRRSIG(domain, keyRR, &rrsig) {
					return true
				}
			}
		}
	}
	return false
}

func validateChainOfTrust(domain string, ksks []DNSKEYResult) bool {
	return validateDS(domain, ksks)
}

func determineDNSSECStatus(zoneApexValid, chainOfTrustValid bool) string {
	if zoneApexValid && chainOfTrustValid {
		return DNSSECFullyImplemented
	}
	if zoneApexValid {
		return DNSSECFailedChainOfTrust
	}
	if chainOfTrustValid {
		return DNSSECFailedZoneApexValidation
	}
	return DNSSECNotImplemented
}

// checkDSExistence checks if DS records exist in the parent zone.
func checkDSExistence(domain string) bool {
	client := NewDNSClient()
	dsRecords, ok := client.LookupDS(domain) // LookupDS now correctly queries the parent
	if !ok {
		return false // Lookup failed (e.g., network error)
	}
	return len(dsRecords) > 0 // DS records exist
}

// validateDS validates DS records against KSKs (Key Signing Keys)
func validateDS(domain string, ksks []DNSKEYResult) bool {
	client := NewDNSClient()

	//dsRecords, ok := client.LookupDS(dns.Fqdn(domain))
	dsRecords, ok := client.LookupDS(domain)
	//if !ok || len(dsRecords) == 0 {
	if !ok || len(dsRecords) == 0 {
		return false
	}

	// For each KSK, try to validate against each DS record
	name := dns.Name(domain)
	slog.Info("validateDS canonical name", "name", name)
	for _, ksk := range ksks {
		dnskey := &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(domain),
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Flags:     ksk.Flags,
			Protocol:  ksk.Protocol,
			Algorithm: ksk.Algorithm,
			PublicKey: ksk.PublicKey,
		}

		for _, dsRecord := range dsRecords {
			ds, err := ParseDS(domain, dsRecord)
			if err != nil {
				continue
			}

			// Generate DS from DNSKEY using same digest type
			generatedDS, err := generateDS(name, dnskey, ds.DigestType)
			if err != nil {
				continue
			}

			// Compare generated DS with retrieved DS
			if compareDS(generatedDS, &dns.DS{
				KeyTag:     ds.KeyTag,
				Algorithm:  ds.Algorithm,
				DigestType: ds.DigestType,
				Digest:     ds.Digest,
			}) {
				slog.Info("valid DS record", "name", name)
				return true
			} else {
				slog.Warn("invalid DS record", "name", name)
			}
		}
	}
	slog.Warn("no DS record found", "name", name)
	return false
}

// generateDS creates a DS record from a DNSKEY using specified digest type
func generateDS(name dns.Name, key *dns.DNSKEY, digestType uint8) (*dns.DS, error) {
	dc := NewDNSClient() // fix this if it works
	parent, err := dc.GetParentZone(string(name))
	slog.Info("generateDS parent", "name", name, "parent", parent)
	if err != nil {
		slog.Error("Parent zone not found", "name", name)
		return nil, err
	}
	ds := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   parent,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		KeyTag:     key.KeyTag(),
		Algorithm:  key.Algorithm,
		DigestType: digestType,
	}

	// Calculate digest based on type
	digest, err := calculateKeyDigest(key, digestType)
	if err != nil {
		return nil, err
	}
	slog.Info("digest type", "name", name, "digest_type", digestType, "digest", digest, "ds_name", ds.Hdr.Name)
	ds.Digest = digest

	return ds, nil
}

// calculateKeyDigest calculates the digest for a DNSKEY
func calculateKeyDigest(key *dns.DNSKEY, digestType uint8) (string, error) {
	dc := NewDNSClient() // fix this if it works
	parent, err := dc.GetParentZone(key.Hdr.Name)
	key.Hdr.Name = parent
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
	key.Hdr.Name = dns.CanonicalName(key.Hdr.Name) // Add this line
	offset, err := dns.PackRR(key, canonical, 0, nil, false)
	if err != nil {
		return "", err
	}
	slog.Info("packed RR", "name", key.Hdr.Name, "offset", offset)

	h.Write(canonical[:offset])
	digest := hex.EncodeToString(h.Sum(nil))
	slog.Info("calculateKeyDigest", "name", key.Hdr.Name, "digest", digest)
	return digest, nil
}

// compareDS compares two DS records
func compareDS(ds1, ds2 *dns.DS) bool {
	// Explicitly lowercase digests for comparison
	digest1 := strings.ToLower(ds1.Digest)
	digest2 := strings.ToLower(ds2.Digest)

	result := ds1.KeyTag == ds2.KeyTag &&
		ds1.Algorithm == ds2.Algorithm &&
		ds1.DigestType == ds2.DigestType &&
		digest1 == digest2

	slog.Info("compareDS", "result", result, "digest1", digest1, "digest2", digest2)
	//log.Printf("compareDS: Comparing KeyTag: %d == %d, Algorithm: %d == %d, DigestType: %d == %d, Digest: %s == %s, Result: %t",
	//    ds1.KeyTag, ds2.KeyTag,
	//    ds1.Algorithm, ds2.Algorithm,
	//    ds1.DigestType, ds2.DigestType,
	//    digest1, digest2, result)

	return result
	//return ds1.KeyTag == ds2.KeyTag &&
	//	ds1.Algorithm == ds2.Algorithm &&
	//	ds1.DigestType == ds2.DigestType &&
	//	strings.EqualFold(ds1.Digest, ds2.Digest)
}
