package scanner

import (
	"log/slog"
	"strings"

	"github.com/danielmichaels/doublestag/internal/config"
	"github.com/danielmichaels/doublestag/internal/logging"
	"github.com/miekg/dns"
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
	ValidationError string
	KSKs            []DNSKEYResult
	ZSKs            []DNSKEYResult
	Details         []string
	HasDNSKEY       bool
	HasDS           bool
	HasRRSIG        bool
}

// todo: a lot of this scanner will need to be moved to an assessor later
type DNSSECScanner struct {
	Result *DNSSECResult
	Client *DNSClient
	logger *slog.Logger
	Domain string
}

func NewDNSSECScanner(domain string) *DNSSECScanner {
	cfg := config.AppConfig()
	logger, _ := logging.SetupLogger("dns-client", cfg)
	domain = dns.Fqdn(domain)
	result := &DNSSECResult{
		Domain: domain,
	}
	client := NewDNSClient()
	return &DNSSECScanner{Domain: domain, Client: client, Result: result, logger: logger}
}

func ScanDNSSEC(domain string) *DNSSECResult {
	ds := NewDNSSECScanner(domain)

	// Check if domain is zone apex
	if !ds.Client.isZoneApex(domain) {
		ds.Result.Status = DNSSECNotApplicable
		return ds.Result
	}

	err := ds.Client.ValidateDNSSEC(domain)
	if err != nil {
		if err.Error() == DNSSECNotImplemented {
			ds.Result.Status = DNSSECNotImplemented
			return ds.Result
		}
		ds.Result.Status = err.Error()
		ds.Result.ValidationError = err.Error()
		return ds.Result
	}
	ds.Result.Status = DNSSECFullyImplemented

	// Retrieve DNSKEY and DS information for the report (optional, for detailed output)
	dnskeys, rrsigs, dnskeyOK := ds.Client.LookupDNSKEYWithRRSIG(domain)
	if dnskeyOK {
		for _, key := range dnskeys {
			parsedKey, _ := ParseDNSKEY(domain, key)
			if parsedKey != nil {
				if parsedKey.Flags == 257 {
					ds.Result.KSKs = append(ds.Result.KSKs, *parsedKey)
				} else if parsedKey.Flags == 256 {
					ds.Result.ZSKs = append(ds.Result.ZSKs, *parsedKey)
				}
			}
		}
		ds.Result.HasDNSKEY = len(dnskeys) > 0
		ds.Result.HasRRSIG = len(rrsigs) > 0
	}

	// Check for DS record but informational purposes only
	dsRecords, dsOK := ds.Client.LookupDS(domain)
	ds.Result.HasDS = dsOK && len(dsRecords) > 0

	if !ds.Result.HasRRSIG || !ds.Result.HasDS || !ds.Result.HasDNSKEY {
		ds.Result.Status = DNSSECNotImplemented
		return ds.Result
	}

	return ds.Result
}

// compareDS compares two DS records
func (c *DNSClient) compareDS(ds1, ds2 *dns.DS) bool {
	// Explicitly lowercase digests for comparison
	digest1 := strings.ToLower(ds1.Digest)
	digest2 := strings.ToLower(ds2.Digest)

	result := ds1.KeyTag == ds2.KeyTag &&
		ds1.Algorithm == ds2.Algorithm &&
		ds1.DigestType == ds2.DigestType &&
		digest1 == digest2

	c.logger.Debug("compareDS",
		"domain", ds1.Hdr.Name,
		"result", result,
		"digest1", digest1,
		"digest2", digest2,
		"algo1", ds1.Algorithm, "algo2", ds2.Algorithm,
		"digestType1", ds1.DigestType, "digestType2", ds2.DigestType,
	)

	return result
}
