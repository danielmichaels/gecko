package detect

import (
	"slices"
	"testing"

	"github.com/danielmichaels/gecko/internal/checks"
)

// TestCNAMEIndeterminateNeverFires is the finding-#2 regression guard: a
// fingerprinted takeover-able provider whose live resolution SERVFAILed must
// produce no finding (it previously fell through to a medium "unconfirmed"), and
// its dangling key must be reported Indeterminate so the reconciler leaves any
// existing finding open rather than resolving it on a transient failure.
func TestCNAMEIndeterminateNeverFires(t *testing.T) {
	d := CNAMEDetector{LongChainThreshold: 8}
	res, err := d.Detect(CNAMEEvidence{Targets: []CNAMETargetEvidence{{
		Target:           "app.herokudns.com",
		ResolutionStatus: ResolutionIndeterminate,
		FPMatched:        true,
		TakeoverProvider: true,
		Provider:         "Heroku",
		ChainLength:      1,
	}}})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(res.Found) != 0 {
		t.Fatalf("SERVFAIL on a takeover provider produced findings: %+v", res.Found)
	}
	want := checks.Key{IssueType: IssueDanglingCNAME, EntityKey: "app.herokudns.com"}
	if !slices.Contains(res.Indeterminate, want) {
		t.Fatalf("dangling key not protected; Indeterminate = %+v", res.Indeterminate)
	}
}

// TestNameserverConfigNoIPv6Indeterminate is the finding-#3 guard: when every AAAA
// lookup failed to complete, the detector must not claim "No IPv6" and must report
// the no_ipv6 key Indeterminate instead.
func TestNameserverConfigNoIPv6Indeterminate(t *testing.T) {
	d := NameserverConfigDetector{RecommendedCount: 2}
	a := healthyNS("ns1.provider-a.com")
	b := healthyNS("ns1.provider-b.net")
	a.AAAAStatus, b.AAAAStatus = ResolutionIndeterminate, ResolutionIndeterminate
	res, err := d.Detect(NameserverConfigEvidence{
		DomainName:  "example.com",
		Nameservers: []NameserverEvidence{a, b},
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	for _, f := range res.Found {
		if f.IssueType == IssueNoIPv6 {
			t.Fatalf("emitted No-IPv6 finding on all-indeterminate AAAA")
		}
	}
	if !slices.Contains(res.Indeterminate, checks.Key{IssueType: IssueNoIPv6}) {
		t.Fatalf("no_ipv6 key not protected; Indeterminate = %+v", res.Indeterminate)
	}
}

// TestNameserverConfigDanglingIndeterminate: a nameserver whose parent-apex SOA
// lookup SERVFAILed must not be flagged dangling, and its dangling_ns key must be
// protected.
func TestNameserverConfigDanglingIndeterminate(t *testing.T) {
	d := NameserverConfigDetector{RecommendedCount: 2}
	ns := healthyNS("ns1.sketchy.example")
	ns.ApexStatus = ResolutionIndeterminate
	res, err := d.Detect(NameserverConfigEvidence{
		DomainName:  "example.com",
		Nameservers: []NameserverEvidence{ns, healthyNS("ns2.provider-b.net")},
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	for _, f := range res.Found {
		if f.IssueType == IssueDanglingNS {
			t.Fatalf("flagged dangling on an indeterminate apex lookup")
		}
	}
	want := checks.Key{IssueType: IssueDanglingNS, EntityKey: "ns1.sketchy.example"}
	if !slices.Contains(res.Indeterminate, want) {
		t.Fatalf("dangling_ns key not protected; Indeterminate = %+v", res.Indeterminate)
	}
}

// TestEmailIndeterminateProtectsMissingKeys guards finding #1 for email: when the
// DMARC and DKIM lookups fail, the missing_* keys are reported Indeterminate (and
// no missing_* finding is emitted) so a SERVFAIL never resolves a real finding.
func TestEmailIndeterminateProtectsMissingKeys(t *testing.T) {
	d := EmailSecurityDetector{MaxSPFLookups: 10, MinDKIMKeyLength: 270, MTASTSMinMaxAge: 604800}
	res, err := d.Detect(EmailSecurityEvidence{
		HandlesEmail: true,
		DMARCStatus:  ResolutionIndeterminate,
		DKIMSelectors: []DKIMSelectorEvidence{
			{Selector: "google", Status: ResolutionIndeterminate},
		},
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	for _, f := range res.Found {
		if f.IssueType == IssueDMARCMissing || f.IssueType == IssueDKIMMissing {
			t.Fatalf("emitted %s on an indeterminate lookup", f.IssueType)
		}
	}
	if !slices.Contains(res.Indeterminate, checks.Key{IssueType: IssueDMARCMissing}) {
		t.Fatalf("missing_dmarc not protected; Indeterminate = %+v", res.Indeterminate)
	}
	if !slices.Contains(res.Indeterminate, checks.Key{IssueType: IssueDKIMMissing}) {
		t.Fatalf("missing_dkim not protected; Indeterminate = %+v", res.Indeterminate)
	}
}
