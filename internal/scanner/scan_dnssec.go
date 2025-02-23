package scanner

import (
	"log/slog"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/dnsrecords"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/logging"
	"github.com/miekg/dns"
)

const (
	DNSSECNotImplemented   = "DNSSEC not implemented"
	DNSSECFullyImplemented = "DNSSEC fully implemented"
	DNSSECNotApplicable    = "DNSSEC not applicable"
)

// todo: a lot of this scanner will need to be moved to an assessor later
type DNSSECScanner struct {
	Result *dnsrecords.DNSSECResult
	Client *dnsclient.DNSClient
	logger *slog.Logger
	Domain string
}

func NewDNSSECScanner(domain string) *DNSSECScanner {
	cfg := config.AppConfig()
	logger, _ := logging.SetupLogger("dns-client", cfg)
	domain = dns.Fqdn(domain)
	result := &dnsrecords.DNSSECResult{
		Domain: domain,
	}
	client := dnsclient.NewDNSClient()
	return &DNSSECScanner{Domain: domain, Client: client, Result: result, logger: logger}
}

func (s *Scan) ScanDNSSEC(domain string) *dnsrecords.DNSSECResult {
	ds := NewDNSSECScanner(domain)

	// Check if domain is zone apex
	if !ds.Client.IsZoneApex(domain) {
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
			parsedKey, _ := dnsrecords.ParseDNSKEY(domain, key)
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
