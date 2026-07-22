package detect

import (
	"sort"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/checks"
)

func emailDetector() EmailSecurityDetector {
	return EmailSecurityDetector{MaxSPFLookups: 10, MinDKIMKeyLength: 270, MTASTSMinMaxAge: 604800}
}

func issueSet(fs []checks.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.IssueType
	}
	sort.Strings(out)
	return out
}

func TestEmailSPF(t *testing.T) {
	d := emailDetector()
	tests := []struct {
		name    string
		records []string
		email   bool
		want    []string
	}{
		{"permit all", []string{"v=spf1 +all"}, true, []string{IssueSPFPermitAll}},
		{
			"bare all is permit all",
			[]string{"v=spf1 include:x all"},
			true,
			[]string{IssueSPFPermitAll},
		},
		{
			"?all weak",
			[]string{"v=spf1 include:_spf.example.com ?all"},
			true,
			[]string{IssueSPFWeakPolicy},
		},
		{
			"~all soft fail",
			[]string{"v=spf1 include:_spf.example.com ~all"},
			true,
			[]string{IssueSPFSoftFail},
		},
		{
			"missing mechanisms (handles email)",
			[]string{"v=spf1 -all"},
			true,
			[]string{IssueSPFMissingMechanism},
		},
		{"compliant hard fail", []string{"v=spf1 include:_spf.example.com -all"}, true, nil},
		{
			"missing all mechanism",
			[]string{"v=spf1 ip4:1.2.3.0/24"},
			true,
			[]string{IssueSPFMissingAll},
		},
		{"missing spf, handles email", nil, true, []string{IssueSPFMissing}},
		{"missing spf, no email -> absence", nil, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := issueSet(
				d.spfFindings(
					EmailSecurityEvidence{SPFRecords: tt.records, HandlesEmail: tt.email},
				),
			)
			assertIssues(t, got, tt.want)
		})
	}

	t.Run("excessive lookups", func(t *testing.T) {
		rec := "v=spf1 include:a include:b include:c include:d include:e include:f include:g include:h include:i include:j include:k -all"
		got := issueSet(
			d.spfFindings(EmailSecurityEvidence{SPFRecords: []string{rec}, HandlesEmail: true}),
		)
		assertIssues(t, got, []string{IssueSPFExcessiveLookups})
	})
}

func TestEmailDKIM(t *testing.T) {
	d := emailDetector()
	longKey := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 300)
	shortKey := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 40)

	t.Run("weak key", func(t *testing.T) {
		ev := EmailSecurityEvidence{HandlesEmail: true, DKIMSelectors: []DKIMSelectorEvidence{
			{Selector: "google", Status: ResolutionData, Records: []string{shortKey}},
		}}
		got := d.dkimFindings(ev)
		assertIssues(t, issueSet(got), []string{IssueDKIMWeakKey})
		if got[0].EntityKey != "google" {
			t.Errorf("dkim entity_key = %q, want selector", got[0].EntityKey)
		}
	})
	t.Run("test mode", func(t *testing.T) {
		ev := EmailSecurityEvidence{HandlesEmail: true, DKIMSelectors: []DKIMSelectorEvidence{
			{Selector: "s1", Status: ResolutionData, Records: []string{longKey + "; t=y"}},
		}}
		assertIssues(t, issueSet(d.dkimFindings(ev)), []string{IssueDKIMTestMode})
	})
	t.Run("compliant -> nothing", func(t *testing.T) {
		ev := EmailSecurityEvidence{HandlesEmail: true, DKIMSelectors: []DKIMSelectorEvidence{
			{Selector: "s1", Status: ResolutionData, Records: []string{longKey}},
		}}
		assertIssues(t, issueSet(d.dkimFindings(ev)), nil)
	})
	t.Run("missing dkim when authoritatively absent", func(t *testing.T) {
		ev := EmailSecurityEvidence{
			HandlesEmail: true, DKIMSelectorsChecked: []string{"google", "s1"},
			DKIMSelectors: []DKIMSelectorEvidence{
				{Selector: "google", Status: ResolutionEmpty},
				{Selector: "s1", Status: ResolutionEmpty},
			},
		}
		assertIssues(t, issueSet(d.dkimFindings(ev)), []string{IssueDKIMMissing})
	})
	t.Run("all SERVFAIL -> no missing_dkim (unknown)", func(t *testing.T) {
		ev := EmailSecurityEvidence{HandlesEmail: true, DKIMSelectors: []DKIMSelectorEvidence{
			{Selector: "google", Status: ResolutionIndeterminate},
			{Selector: "s1", Status: ResolutionIndeterminate},
		}}
		assertIssues(t, issueSet(d.dkimFindings(ev)), nil)
	})
}

func TestEmailDMARC(t *testing.T) {
	tests := []struct {
		name   string
		status string
		record string
		email  bool
		want   []string
	}{
		{
			"p=none weak",
			ResolutionData,
			"v=DMARC1; p=none; rua=mailto:r@x; ruf=mailto:r@x",
			true,
			[]string{IssueDMARCWeakPolicy},
		},
		{
			"quarantine",
			ResolutionData,
			"v=DMARC1; p=quarantine; rua=mailto:r@x; ruf=mailto:r@x",
			true,
			[]string{IssueDMARCQuarantine},
		},
		{
			"reject compliant -> nothing",
			ResolutionData,
			"v=DMARC1; p=reject; rua=mailto:r@x; ruf=mailto:r@x",
			true,
			nil,
		},
		{
			"reduced pct",
			ResolutionData,
			"v=DMARC1; p=reject; pct=50; rua=mailto:r@x; ruf=mailto:r@x",
			true,
			[]string{IssueDMARCReducedPct},
		},
		{
			"weak subdomain",
			ResolutionData,
			"v=DMARC1; p=reject; sp=none; rua=mailto:r@x; ruf=mailto:r@x",
			true,
			[]string{IssueDMARCWeakSubPol},
		},
		{
			"missing tags",
			ResolutionData,
			"v=DMARC1; p=reject",
			true,
			[]string{IssueDMARCMissingTags},
		},
		{"missing record + email", ResolutionEmpty, "", true, []string{IssueDMARCMissing}},
		{"missing record, no email -> absence", ResolutionEmpty, "", false, nil},
		{"indeterminate -> nothing", ResolutionIndeterminate, "", true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := EmailSecurityEvidence{DMARCStatus: tt.status, HandlesEmail: tt.email}
			if tt.record != "" {
				ev.DMARCRecords = []string{tt.record}
			}
			assertIssues(t, issueSet(dmarcFindings(ev)), tt.want)
		})
	}
}

func TestEmailBIMI(t *testing.T) {
	enforced := []string{"v=DMARC1; p=reject"}
	tests := []struct {
		name string
		ev   EmailSecurityEvidence
		want []string
	}{
		{"no bimi -> nothing", EmailSecurityEvidence{HandlesEmail: true}, nil},
		{
			"not email -> nothing",
			EmailSecurityEvidence{BIMIRecord: "v=BIMI1; l=https://x/logo.svg"},
			nil,
		},
		{
			"dmarc not enforced",
			EmailSecurityEvidence{HandlesEmail: true, BIMIRecord: "v=BIMI1; l=https://x/logo.svg"},
			[]string{IssueBIMIRequiresDMARC},
		},
		{
			"invalid logo (not svg)",
			EmailSecurityEvidence{
				HandlesEmail: true,
				DMARCRecords: enforced,
				BIMIRecord:   "v=BIMI1; l=https://x/logo.png",
			},
			[]string{IssueBIMIInvalidLogo},
		},
		{
			"invalid vmc",
			EmailSecurityEvidence{
				HandlesEmail: true,
				DMARCRecords: enforced,
				BIMIRecord:   "v=BIMI1; l=https://x/logo.svg; a=http://x/vmc.pem",
			},
			[]string{IssueBIMIInvalidVMC},
		},
		{
			"compliant -> nothing",
			EmailSecurityEvidence{
				HandlesEmail: true,
				DMARCRecords: enforced,
				BIMIRecord:   "v=BIMI1; l=https://x/logo.svg",
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertIssues(t, issueSet(bimiFindings(tt.ev)), tt.want)
		})
	}
}

func TestEmailMTASTS(t *testing.T) {
	d := emailDetector()
	goodPolicy := "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800"
	base := func() EmailSecurityEvidence {
		return EmailSecurityEvidence{
			HandlesEmail: true, MTASTSConfigured: true, MTASTSPolicyReached: true,
			MTASTSPolicyStatus: 200, MTASTSPolicyBody: goodPolicy, MXTargets: []string{"mail.example.com"},
		}
	}
	tests := []struct {
		name   string
		mutate func(*EmailSecurityEvidence)
		want   []string
	}{
		{"compliant -> nothing", func(*EmailSecurityEvidence) {}, nil},
		{
			"not configured -> nothing",
			func(e *EmailSecurityEvidence) { e.MTASTSConfigured = false },
			nil,
		},
		{
			"policy unreachable",
			func(e *EmailSecurityEvidence) { e.MTASTSPolicyReached = false },
			[]string{IssueMTASTSPolicyUnreachable},
		},
		{
			"non-200 unreachable",
			func(e *EmailSecurityEvidence) { e.MTASTSPolicyStatus = 404 },
			[]string{IssueMTASTSPolicyUnreachable},
		},
		{"mode not enforcing", func(e *EmailSecurityEvidence) {
			e.MTASTSPolicyBody = "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800"
		}, []string{IssueMTASTSModeNotEnforcing}},
		{
			"mx mismatch",
			func(e *EmailSecurityEvidence) { e.MXTargets = []string{"other.example.net"} },
			[]string{IssueMTASTSMXMismatch},
		},
		{"short max age", func(e *EmailSecurityEvidence) {
			e.MTASTSPolicyBody = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 3600"
		}, []string{IssueMTASTSShortMaxAge}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := base()
			tt.mutate(&ev)
			assertIssues(t, issueSet(d.mtaStsFindings(ev)), tt.want)
		})
	}
}

func TestEmailTLSRPT(t *testing.T) {
	tests := []struct {
		name string
		ev   EmailSecurityEvidence
		want []string
	}{
		{"not configured -> nothing", EmailSecurityEvidence{HandlesEmail: true}, nil},
		{
			"invalid rua",
			EmailSecurityEvidence{HandlesEmail: true, TLSRPTRecord: "v=TLSRPTv1; rua=ftp://x"},
			[]string{IssueTLSRPTInvalidRua},
		},
		{
			"valid mailto -> nothing",
			EmailSecurityEvidence{HandlesEmail: true, TLSRPTRecord: "v=TLSRPTv1; rua=mailto:r@x"},
			nil,
		},
		{
			"valid https -> nothing",
			EmailSecurityEvidence{
				HandlesEmail: true,
				TLSRPTRecord: "v=TLSRPTv1; rua=https://x/report",
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertIssues(t, issueSet(tlsRptFindings(tt.ev)), tt.want)
		})
	}
}

func assertIssues(t *testing.T, got, want []string) {
	t.Helper()
	w := append([]string(nil), want...)
	sort.Strings(w)
	if !equalStrings(got, w) {
		t.Fatalf("issues = %v, want %v", got, w)
	}
}
