package scanner

import (
	"github.com/danielmichaels/doublestag/internal/dnsclient"
	"github.com/danielmichaels/doublestag/internal/dnsrecords"
)

func (s *Scan) ScanZoneTransfer(domain string) *dnsrecords.ZoneTransferResult {
	client := dnsclient.NewDNSClient()
	result := client.AttemptZoneTransfer(domain)
	return result
}
