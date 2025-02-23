package scanner

import (
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/dnsrecords"
)

func (s *Scan) ScanZoneTransfer(domain string) *dnsrecords.ZoneTransferResult {
	client := dnsclient.NewDNSClient()
	result := client.AttemptZoneTransfer(domain)
	return result
}
