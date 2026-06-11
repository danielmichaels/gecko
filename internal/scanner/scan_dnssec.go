package scanner

import (
	"context"
	"log/slog"
	"strconv"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"

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
	Client dnsclient.Resolver
	logger *slog.Logger
	Domain string
}

func NewDNSSECScanner(domain string, client dnsclient.Resolver) *DNSSECScanner {
	cfg := config.AppConfig()
	logger, _ := logging.SetupLogger("dns-client", cfg)
	domain = dns.Fqdn(domain)
	result := &dnsrecords.DNSSECResult{
		Domain: domain,
	}
	return &DNSSECScanner{Domain: domain, Client: client, Result: result, logger: logger}
}

func (s *Scan) ScanDNSSEC(ctx context.Context, domain string) *dnsrecords.DNSSECResult {
	ds := NewDNSSECScanner(domain, s.resolver)
	defer func() { s.storeDNSSEC(ctx, ds.Result) }()

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
				switch parsedKey.Flags {
				case 257:
					ds.Result.KSKs = append(ds.Result.KSKs, *parsedKey)
				case 256:
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

// storeDNSSEC upserts the DNSSEC scan state into the live projection table and
// emits its observation. It is a no-op without a real scan identity (zero
// DomainID in unit tests).
func (s *Scan) storeDNSSEC(ctx context.Context, result *dnsrecords.DNSSECResult) {
	if s.identity.DomainID == 0 || s.store == nil || result == nil {
		return
	}
	algorithms := collectDNSSECAlgorithms(result)
	validationError := pgtype.Text{
		String: result.ValidationError,
		Valid:  result.ValidationError != "",
	}
	_, err := s.store.ScannersStoreDNSSECResult(ctx, store.ScannersStoreDNSSECResultParams{
		DomainID:        pgtype.Int4{Int32: s.identity.DomainID, Valid: true},
		Status:          result.Status,
		ValidationError: validationError,
		HasDnskey:       result.HasDNSKEY,
		HasDs:           result.HasDS,
		HasRrsig:        result.HasRRSIG,
		Algorithms:      algorithms,
	})
	if err != nil {
		s.logger.Error("failed to store dnssec scan result", "error", err)
		return
	}

	payload := observer.PayloadJSON(map[string]any{
		"status":     result.Status,
		"has_dnskey": result.HasDNSKEY,
		"has_ds":     result.HasDS,
		"has_rrsig":  result.HasRRSIG,
		"algorithms": algorithms,
	})
	if err := observer.New(s.store).RecordFindingChange(
		ctx, s.identity, observer.EntityDNSSEC, "dnssec", payload,
	); err != nil {
		s.logger.Error("failed to emit dnssec observation", "error", err)
	}
}

// collectDNSSECAlgorithms returns the distinct signing-algorithm numbers (as
// strings) present across the KSK and ZSK key material, preserving first-seen
// order. Never returns nil so the NOT NULL array column is satisfied.
func collectDNSSECAlgorithms(result *dnsrecords.DNSSECResult) []string {
	seen := make(map[string]bool)
	algorithms := []string{}
	for _, key := range append(append([]dnsrecords.DNSKEYResult{}, result.KSKs...), result.ZSKs...) {
		alg := strconv.Itoa(int(key.Algorithm))
		if !seen[alg] {
			seen[alg] = true
			algorithms = append(algorithms, alg)
		}
	}
	return algorithms
}
