package detect

import "testing"

func TestDNSSECDetect(t *testing.T) {
	d := DNSSECDetector{}
	tests := []struct {
		name    string
		ev      DNSSECEvidence
		wantIT  string // "" = no finding
		wantSev string
	}{
		{"not fetched -> nothing", DNSSECEvidence{Fetched: false}, "", ""},
		{"not applicable (non-apex) -> nothing", DNSSECEvidence{Fetched: true, NotApplicable: true, HasDNSKEY: true}, "", ""},
		{"validation error -> broken chain high", DNSSECEvidence{Fetched: true, ValidationError: "no valid RRSIG", HasDNSKEY: true, HasDS: true, HasRRSIG: true}, IssueDNSSECBrokenChain, "high"},
		{"not enabled (none present) -> nothing", DNSSECEvidence{Fetched: true}, "", ""},
		{"fully signed, modern algo -> nothing", DNSSECEvidence{Fetched: true, HasDNSKEY: true, HasDS: true, HasRRSIG: true, Algorithms: []string{"13"}}, "", ""},
		{"fully signed, deprecated algo -> weak medium", DNSSECEvidence{Fetched: true, HasDNSKEY: true, HasDS: true, HasRRSIG: true, Algorithms: []string{"13", "5"}}, IssueDNSSECWeakAlgorithm, "medium"},
		{"partial (only DNSKEY) -> broken chain high", DNSSECEvidence{Fetched: true, HasDNSKEY: true}, IssueDNSSECBrokenChain, "high"},
		{"partial (DS without RRSIG) -> broken chain high", DNSSECEvidence{Fetched: true, HasDNSKEY: true, HasDS: true}, IssueDNSSECBrokenChain, "high"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Detect(tt.ev)
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantIT == "" {
				if len(got) != 0 {
					t.Fatalf("got %d findings, want 0: %+v", len(got), got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1", len(got))
			}
			if got[0].IssueType != tt.wantIT {
				t.Errorf("issue_type = %q, want %q", got[0].IssueType, tt.wantIT)
			}
			if got[0].Severity != tt.wantSev {
				t.Errorf("severity = %q, want %q", got[0].Severity, tt.wantSev)
			}
			if got[0].EntityKey != "" {
				t.Errorf("entity_key = %q, want empty", got[0].EntityKey)
			}
		})
	}
}
