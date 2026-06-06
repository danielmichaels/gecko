package dnsclient

import (
	"context"

	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

// Resolver is the seam between scanners/assessors and DNS egress. It is the exact
// method set callers use today; *DNSClient satisfies it unchanged. A future
// caching/singleflight/rate-limiting implementation swaps in here with no call-site
// changes.
type Resolver interface {
	LookupA(target string) ([]string, bool)
	LookupAAAA(target string) ([]string, bool)
	LookupCNAME(target string) ([]string, bool)
	LookupTXT(target string) ([]string, bool)
	LookupDS(target string) ([]string, bool)
	LookupDNSKEYWithRRSIG(target string) ([]string, []string, bool)
	LookupWithStatus(target string, qtype uint16) ([]string, ResolutionStatus)
	IsZoneApex(domain string) bool
	ValidateDNSSEC(domain string) error
	AttemptZoneTransfer(domain string) *dnsrecords.ZoneTransferResult
	EnumerateWithSubfinderCallback(
		ctx context.Context,
		domain string,
		concurrency int,
		callback func(*resolve.HostEntry),
	) error
}

var _ Resolver = (*DNSClient)(nil)
