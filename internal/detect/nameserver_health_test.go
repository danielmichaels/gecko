package detect

import (
	"sort"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/checks"
)

func nsHealthDetector() NameserverHealthDetector {
	return NameserverHealthDetector{LatencyInfoMs: 150, LatencyLowMs: 400, LatencyMediumMs: 900}
}

// healthyProbe is reachable over UDP+TCP, EDNS-capable, fast, with a serial.
func healthyProbe(ns, serial string) NameserverProbeEvidence {
	return NameserverProbeEvidence{
		Nameserver: ns, Probed: true, Reached: true, TCPProbed: true, TCPOK: true,
		HasEDNS: true, LatencyMs: 50, ApexSerial: serial,
	}
}

func nsHealthKeys(fs []checks.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.IssueType + "@" + f.EntityKey
	}
	sort.Strings(out)
	return out
}

func TestNameserverHealthReachability(t *testing.T) {
	d := nsHealthDetector()
	tests := []struct {
		name   string
		probe  NameserverProbeEvidence
		wantIT string
	}{
		{"healthy -> nothing", healthyProbe("ns1.example.com", "2026072201"), ""},
		{
			"probed but not reached -> unreachable",
			NameserverProbeEvidence{Nameserver: "ns1.example.com", Probed: true, Reached: false},
			IssueNSUnreachable,
		},
		{
			"not probed (rate limited) -> nothing",
			NameserverProbeEvidence{Nameserver: "ns1.example.com", Probed: false},
			"",
		},
		{
			"reached, tcp probed but fails -> no_tcp",
			NameserverProbeEvidence{
				Nameserver: "ns1.example.com",
				Probed:     true,
				Reached:    true,
				TCPProbed:  true,
				TCPOK:      false,
				HasEDNS:    true,
				LatencyMs:  50,
			},
			IssueNSNoTCPSupport,
		},
		{
			"reached, no edns -> no_edns",
			NameserverProbeEvidence{
				Nameserver: "ns1.example.com",
				Probed:     true,
				Reached:    true,
				TCPProbed:  true,
				TCPOK:      true,
				HasEDNS:    false,
				LatencyMs:  50,
			},
			IssueNSNoEDNSSupport,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findingsOf(d.Detect(
				NameserverHealthEvidence{
					RecordType:  "SOA",
					Nameservers: []NameserverProbeEvidence{tt.probe},
				},
			))
			var its []string
			for _, f := range got {
				its = append(its, f.IssueType)
			}
			if tt.wantIT == "" {
				if len(got) != 0 {
					t.Fatalf("want nothing, got %v", its)
				}
				return
			}
			found := false
			for _, f := range got {
				if f.IssueType == tt.wantIT {
					found = true
					if f.EntityKey != tt.probe.Nameserver {
						t.Errorf("entity_key = %q, want nameserver", f.EntityKey)
					}
				}
			}
			if !found {
				t.Fatalf("want %s, got %v", tt.wantIT, its)
			}
		})
	}
}

func TestNameserverHealthLatencyTiers(t *testing.T) {
	d := nsHealthDetector()
	tests := []struct {
		ms      int32
		wantSev string // "" = no finding
	}{
		{
			50,
			"",
		}, {149, ""}, {150, "info"}, {399, "info"}, {400, "low"}, {899, "low"}, {900, "medium"}, {5000, "medium"},
	}
	for _, tt := range tests {
		p := healthyProbe("ns1.example.com", "2026072201")
		p.LatencyMs = tt.ms
		got := findingsOf(d.Detect(
			NameserverHealthEvidence{RecordType: "SOA", Nameservers: []NameserverProbeEvidence{p}},
		))
		var sev string
		for _, f := range got {
			if f.IssueType == IssueNSHighLatency {
				sev = f.Severity
				if f.EntityKey != "ns1.example.com|SOA" {
					t.Errorf("latency entity_key = %q, want composite", f.EntityKey)
				}
			}
		}
		if sev != tt.wantSev {
			t.Errorf("latency %dms -> severity %q, want %q", tt.ms, sev, tt.wantSev)
		}
	}
}

func TestNameserverHealthConsistency(t *testing.T) {
	d := nsHealthDetector()

	t.Run("agreeing serials -> nothing", func(t *testing.T) {
		got := findingsOf(d.Detect(
			NameserverHealthEvidence{RecordType: "SOA", Nameservers: []NameserverProbeEvidence{
				healthyProbe("ns1.example.com", "2026072201"),
				healthyProbe("ns2.example.com", "2026072201"),
			}},
		))
		for _, f := range got {
			if f.IssueType == IssueNSResolverMismatch {
				t.Fatal("agreeing serials wrongly flagged")
			}
		}
	})

	t.Run("divergent serials -> resolver_mismatch low, keyed by record_type", func(t *testing.T) {
		got := findingsOf(d.Detect(
			NameserverHealthEvidence{RecordType: "SOA", Nameservers: []NameserverProbeEvidence{
				healthyProbe("ns1.example.com", "2026072201"),
				healthyProbe("ns2.example.com", "2026072199"),
			}},
		))
		var f *checks.Finding
		for i := range got {
			if got[i].IssueType == IssueNSResolverMismatch {
				f = &got[i]
			}
		}
		if f == nil {
			t.Fatalf("expected resolver_mismatch, got %v", nsHealthKeys(got))
		}
		if f.Severity != "low" || f.EntityKey != "SOA" {
			t.Errorf("severity=%q entity_key=%q, want low/SOA", f.Severity, f.EntityKey)
		}
		if !strings.Contains(f.Details, "ns2.example.com") {
			t.Errorf("details missing divergent ns: %s", f.Details)
		}
	})

	t.Run("unreached nameservers excluded from consistency", func(t *testing.T) {
		got := findingsOf(d.Detect(
			NameserverHealthEvidence{RecordType: "SOA", Nameservers: []NameserverProbeEvidence{
				healthyProbe("ns1.example.com", "2026072201"),
				{Nameserver: "ns2.example.com", Probed: true, Reached: false},
			}},
		))
		for _, f := range got {
			if f.IssueType == IssueNSResolverMismatch {
				t.Fatal("unreached NS should not create a divergence")
			}
		}
	})
}
