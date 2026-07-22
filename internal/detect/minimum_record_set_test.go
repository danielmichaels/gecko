package detect

import (
	"sort"
	"testing"

	"github.com/danielmichaels/gecko/internal/checks"
)

func healthyApex() MinimumRecordSetEvidence {
	return MinimumRecordSetEvidence{
		IsApex:           true,
		NSLookedUp:       true,
		NSCount:          2,
		ALookedUp:        true,
		HasA:             true,
		AAAALookedUp:     true,
		HasAAAA:          true,
		SOALookedUp:      true,
		SOAPresent:       true,
		SOARefresh:       3600,
		SOARetry:         600,
		SOAExpire:        1209600,
		SOAMinimumTTL:    3600,
		SOASerial:        2026072201,
		SOAMName:         "ns1.example.com",
		SOAMNameLookedUp: true,
		SOAMNameResolves: true,
		SOARName:         "hostmaster.example.com",
		MXLookedUp:       true,
		HasMX:            true,
	}
}

func minRecordIssues(fs []checks.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.IssueType
	}
	sort.Strings(out)
	return out
}

func TestMinimumRecordSetDetect(t *testing.T) {
	d := MinimumRecordSetDetector{MinNameservers: 2}
	tests := []struct {
		name   string
		mutate func(*MinimumRecordSetEvidence)
		want   []string
	}{
		{"healthy apex -> nothing", func(*MinimumRecordSetEvidence) {}, nil},
		{"non-apex -> nothing", func(e *MinimumRecordSetEvidence) {
			*e = MinimumRecordSetEvidence{IsApex: false, NSCount: 0, NSLookedUp: true}
		}, nil},
		{
			"too few nameservers",
			func(e *MinimumRecordSetEvidence) { e.NSCount = 1 },
			[]string{IssueInsufficientNameservers},
		},
		{
			"ns lookup failed -> no ns finding",
			func(e *MinimumRecordSetEvidence) { e.NSLookedUp = false; e.NSCount = 0 },
			nil,
		},
		{
			"no apex address",
			func(e *MinimumRecordSetEvidence) { e.HasA = false; e.HasAAAA = false },
			[]string{IssueMissingApexAddress},
		},
		{
			"missing ipv6",
			func(e *MinimumRecordSetEvidence) { e.HasAAAA = false },
			[]string{IssueMissingIPv6},
		},
		{
			"missing soa",
			func(e *MinimumRecordSetEvidence) { e.SOAPresent = false },
			[]string{IssueMissingSOA},
		},
		{
			"soa timers out of range",
			func(e *MinimumRecordSetEvidence) { e.SOARefresh = 60 },
			[]string{IssueSOATimersOutOfRange},
		},
		{
			"soa serial not date-based",
			func(e *MinimumRecordSetEvidence) { e.SOASerial = 42 },
			[]string{IssueSOASerialFormat},
		},
		{
			"soa mname unresolvable",
			func(e *MinimumRecordSetEvidence) { e.SOAMNameResolves = false },
			[]string{IssueSOAMNameUnresolvable},
		},
		{
			"soa mname lookup failed -> nothing",
			func(e *MinimumRecordSetEvidence) { e.SOAMNameLookedUp = false; e.SOAMNameResolves = false },
			nil,
		},
		{
			"soa rname malformed",
			func(e *MinimumRecordSetEvidence) { e.SOARName = "nolocalpart" },
			[]string{IssueSOARNameMalformed},
		},
		{
			"missing mx with email intent",
			func(e *MinimumRecordSetEvidence) { e.HasMX = false; e.TXTValues = []string{"v=spf1 -all"} },
			[]string{IssueMissingMX},
		},
		{
			"missing mx without email intent -> nothing",
			func(e *MinimumRecordSetEvidence) { e.HasMX = false },
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := healthyApex()
			tt.mutate(&ev)
			got, err := d.Detect(ev)
			if err != nil {
				t.Fatal(err)
			}
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if !equalStrings(minRecordIssues(got), want) {
				t.Fatalf("issues = %v, want %v", minRecordIssues(got), want)
			}
		})
	}
}
