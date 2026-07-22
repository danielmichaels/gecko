package detect

import (
	"sort"
	"testing"

	"github.com/danielmichaels/gecko/internal/checks"
)

func caaIssues(fs []checks.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.IssueType
	}
	sort.Strings(out)
	return out
}

func rec(tag, value string) CAARecord { return CAARecord{Tag: tag, Value: value} }

func TestCAADetect(t *testing.T) {
	d := CAADetector{}
	tests := []struct {
		name string
		ev   CAAEvidence
		want []string
	}{
		{"lookup failed -> nothing", CAAEvidence{LookedUp: false}, nil},
		{
			name: "no records, no cert -> caa_missing only",
			ev:   CAAEvidence{LookedUp: true, HasCert: false},
			want: []string{IssueCAAMissing},
		},
		{
			name: "no records, has cert -> caa_missing + required_for_cert",
			ev:   CAAEvidence{LookedUp: true, HasCert: true},
			want: []string{IssueCAAMissing, IssueCAARequiredForCert},
		},
		{
			name: "trusted issuer + iodef -> compliant (nothing)",
			ev: CAAEvidence{LookedUp: true, Records: []CAARecord{
				rec("issue", "letsencrypt.org"), rec("iodef", "mailto:sec@example.com"),
			}},
			want: nil,
		},
		{
			name: "only iodef, no issue tag -> allows_any_ca",
			ev:   CAAEvidence{LookedUp: true, Records: []CAARecord{rec("iodef", "mailto:sec@example.com")}},
			want: []string{IssueCAAAllowsAnyCA},
		},
		{
			name: "untrusted issuer, no iodef -> untrusted + missing_iodef",
			ev:   CAAEvidence{LookedUp: true, Records: []CAARecord{rec("issue", "sketchy-ca.example")}},
			want: []string{IssueCAAMissingIodef, IssueCAAUntrustedIssuer},
		},
		{
			name: "no-issuance + permissive issue -> conflicting (+untrusted +missing_iodef)",
			ev: CAAEvidence{LookedUp: true, Records: []CAARecord{
				rec("issue", ";"), rec("issue", "sketchy-ca.example"),
			}},
			want: []string{IssueCAAConflictingRecords, IssueCAAMissingIodef, IssueCAAUntrustedIssuer},
		},
		{
			name: "unknown tag with critical flag -> unknown_critical (+missing_iodef, +allows_any_ca)",
			ev: CAAEvidence{LookedUp: true, Records: []CAARecord{
				{Tag: "weirdprop", Value: "x", Flags: 128},
			}},
			want: []string{IssueCAAAllowsAnyCA, IssueCAAMissingIodef, IssueCAAUnknownCriticalFlag},
		},
		{
			name: "issuewild untrusted contributes issuer but not any-ca (issue present)",
			ev: CAAEvidence{LookedUp: true, Records: []CAARecord{
				rec("issue", "letsencrypt.org"), rec("issuewild", "sketchy-ca.example"),
				rec("iodef", "mailto:x@example.com"),
			}},
			want: []string{IssueCAAUntrustedIssuer},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Detect(tt.ev)
			if err != nil {
				t.Fatal(err)
			}
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if !equalStrings(caaIssues(got), want) {
				t.Fatalf("issues = %v, want %v", caaIssues(got), want)
			}
			for _, f := range got {
				if f.EntityKey != "" {
					t.Errorf("entity_key = %q, want empty for caa", f.EntityKey)
				}
			}
		})
	}
}
