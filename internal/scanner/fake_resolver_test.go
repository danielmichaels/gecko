package scanner

import (
	"context"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

type fakeResolver struct {
	cnameReturn []string
	cnameOK     bool
	aReturn     []string
	aOK         bool
	aaaaReturn  []string
	aaaaOK      bool

	zoneTransferReturn *dnsrecords.ZoneTransferResult

	calledCNAME        []string
	calledA            []string
	calledAAAA         []string
	calledZoneTransfer []string
}

func (f *fakeResolver) LookupCNAME(target string) ([]string, bool) {
	f.calledCNAME = append(f.calledCNAME, target)
	return f.cnameReturn, f.cnameOK
}

func (f *fakeResolver) LookupA(target string) ([]string, bool) {
	f.calledA = append(f.calledA, target)
	return f.aReturn, f.aOK
}

func (f *fakeResolver) LookupAAAA(target string) ([]string, bool) {
	f.calledAAAA = append(f.calledAAAA, target)
	return f.aaaaReturn, f.aaaaOK
}
func (f *fakeResolver) LookupTXT(string) ([]string, bool) { return nil, false }
func (f *fakeResolver) LookupDS(string) ([]string, bool)  { return nil, false }
func (f *fakeResolver) LookupDNSKEYWithRRSIG(string) ([]string, []string, bool) {
	return nil, nil, false
}

func (f *fakeResolver) LookupWithStatus(string, uint16) ([]string, dnsclient.ResolutionStatus) {
	return nil, dnsclient.ResolutionIndeterminate
}
func (f *fakeResolver) IsZoneApex(string) bool      { return false }
func (f *fakeResolver) ValidateDNSSEC(string) error { return nil }
func (f *fakeResolver) AttemptZoneTransfer(domain string) *dnsrecords.ZoneTransferResult {
	f.calledZoneTransfer = append(f.calledZoneTransfer, domain)
	if f.zoneTransferReturn != nil {
		return f.zoneTransferReturn
	}
	return &dnsrecords.ZoneTransferResult{}
}

func (f *fakeResolver) EnumerateWithSubfinderCallback(
	context.Context, string, int, func(*resolve.HostEntry),
) error {
	return nil
}

var _ dnsclient.Resolver = (*fakeResolver)(nil)
