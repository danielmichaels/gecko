package assessor

import (
	"context"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

type stubResponse struct {
	records []string
	status  dnsclient.ResolutionStatus
}

// fakeResolver returns authoritative empty results for unspecified names.
type fakeResolver struct {
	responses map[string]stubResponse
	called    []string
}

func (f *fakeResolver) LookupWithStatus(
	target string,
	_ uint16,
) ([]string, dnsclient.ResolutionStatus) {
	f.called = append(f.called, target)
	if r, ok := f.responses[target]; ok {
		return r.records, r.status
	}
	return nil, dnsclient.ResolutionEmpty
}

func (f *fakeResolver) LookupA(string) ([]string, bool)    { return nil, false }
func (f *fakeResolver) LookupAAAA(string) ([]string, bool) { return nil, false }
func (f *fakeResolver) LookupCNAME(string) ([]string, bool) {
	return nil, false
}
func (f *fakeResolver) LookupTXT(string) ([]string, bool) { return nil, false }
func (f *fakeResolver) LookupDS(string) ([]string, bool)  { return nil, false }
func (f *fakeResolver) LookupDNSKEYWithRRSIG(string) ([]string, []string, bool) {
	return nil, nil, false
}
func (f *fakeResolver) IsZoneApex(string) bool      { return false }
func (f *fakeResolver) ValidateDNSSEC(string) error { return nil }
func (f *fakeResolver) AttemptZoneTransfer(string) *dnsrecords.ZoneTransferResult {
	return &dnsrecords.ZoneTransferResult{}
}

func (f *fakeResolver) EnumerateWithSubfinderCallback(
	context.Context, string, int, func(*resolve.HostEntry),
) error {
	return nil
}

var _ dnsclient.Resolver = (*fakeResolver)(nil)
