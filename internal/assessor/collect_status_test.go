package assessor

import (
	"fmt"
	"testing"

	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/danielmichaels/gecko/internal/dnsclient"
)

func data(records ...string) stubResponse {
	return stubResponse{records: records, status: dnsclient.ResolutionData}
}

var servfail = stubResponse{status: dnsclient.ResolutionIndeterminate}

func endlessChain() map[string]stubResponse {
	out := make(map[string]stubResponse, maxChainDepth*2)
	for i := range maxChainDepth * 2 {
		out[fmt.Sprintf("hop%d.example.com", i)] = data(fmt.Sprintf("hop%d.example.com", i+1))
	}
	return out
}

func TestWalkCNAMEChainStatus(t *testing.T) {
	tests := []struct {
		name       string
		responses  map[string]stubResponse
		start      string
		wantLength int
		wantLooped bool
		wantStatus dnsclient.ResolutionStatus
	}{
		{
			name:       "chain ends authoritatively",
			responses:  map[string]stubResponse{"a.example.com": data("b.example.com")},
			start:      "a.example.com",
			wantLength: 2,
			wantStatus: dnsclient.ResolutionEmpty,
		},
		{
			name: "loop is a real observation",
			responses: map[string]stubResponse{
				"a.example.com": data("b.example.com"),
				"b.example.com": data("a.example.com"),
			},
			start:      "a.example.com",
			wantLength: 3,
			wantLooped: true,
			wantStatus: dnsclient.ResolutionData,
		},
		{
			name: "failed hop truncates the walk",
			responses: map[string]stubResponse{
				"a.example.com": data("b.example.com"),
				"b.example.com": servfail,
			},
			start:      "a.example.com",
			wantLength: 2,
			wantStatus: dnsclient.ResolutionIndeterminate,
		},
		{
			name:       "depth limit is not termination",
			responses:  endlessChain(),
			start:      "hop0.example.com",
			wantLength: maxChainDepth,
			wantStatus: dnsclient.ResolutionIndeterminate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Assessor{dnsClient: &fakeResolver{responses: tt.responses}}
			length, looped, status := a.walkCNAMEChain(tt.start)
			if length != tt.wantLength || looped != tt.wantLooped || status != tt.wantStatus {
				t.Fatalf("walk = (%d, %v, %v), want (%d, %v, %v)",
					length, looped, status, tt.wantLength, tt.wantLooped, tt.wantStatus)
			}
		})
	}
}

func TestPresenceLookupsCarryStatus(t *testing.T) {
	const name = "example.com"
	bimiName := "default._bimi." + name

	t.Run("published record resolves with data", func(t *testing.T) {
		a := &Assessor{dnsClient: &fakeResolver{responses: map[string]stubResponse{
			bimiName: data("v=BIMI1; l=https://x/logo.svg"),
		}}}
		rec, st := a.lookupBIMIRecord(name)
		if rec == "" || resolutionString(st) != detect.ResolutionData {
			t.Fatalf("bimi = (%q, %v), want a record with data status", rec, st)
		}
	})
	t.Run("authoritative absence is determinate", func(t *testing.T) {
		a := &Assessor{dnsClient: &fakeResolver{responses: map[string]stubResponse{}}}
		rec, st := a.lookupBIMIRecord(name)
		if rec != "" || resolutionString(st) != detect.ResolutionEmpty {
			t.Fatalf("bimi = (%q, %v), want empty/empty", rec, st)
		}
	})
	t.Run("failed lookup is indeterminate", func(t *testing.T) {
		a := &Assessor{dnsClient: &fakeResolver{responses: map[string]stubResponse{
			bimiName: servfail,
		}}}
		rec, st := a.lookupBIMIRecord(name)
		if rec != "" || resolutionString(st) != detect.ResolutionIndeterminate {
			t.Fatalf("bimi = (%q, %v), want empty/indeterminate", rec, st)
		}
	})
	t.Run("prefixed TXT failure is indeterminate", func(t *testing.T) {
		a := &Assessor{dnsClient: &fakeResolver{responses: map[string]stubResponse{
			"_mta-sts." + name: servfail,
		}}}
		rec, st := a.lookupTXTPrefixed("_mta-sts."+name, "v=STSv1")
		if rec != "" || resolutionString(st) != detect.ResolutionIndeterminate {
			t.Fatalf("mta-sts = (%q, %v), want empty/indeterminate", rec, st)
		}
	})
	t.Run("data without the prefix is authoritative absence", func(t *testing.T) {
		a := &Assessor{dnsClient: &fakeResolver{responses: map[string]stubResponse{
			"_smtp._tls." + name: data("some other txt record"),
		}}}
		rec, st := a.lookupTXTPrefixed("_smtp._tls."+name, "v=TLSRPTv1")
		if rec != "" || resolutionString(st) != detect.ResolutionData {
			t.Fatalf("tls-rpt = (%q, %v), want empty record with data status", rec, st)
		}
	})
}
