package detect

import (
	"slices"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/checks"
)

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

func TestDKIMMissingNeedsEverySelectorDeterminate(t *testing.T) {
	d := emailDetector()
	res, err := d.Detect(EmailSecurityEvidence{
		HandlesEmail:         true,
		DKIMSelectorsChecked: []string{"google", "s1"},
		DKIMSelectors: []DKIMSelectorEvidence{
			{Selector: "google", Status: ResolutionEmpty},
			{Selector: "s1", Status: ResolutionIndeterminate},
		},
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	for _, f := range res.Found {
		if f.IssueType == IssueDKIMMissing {
			t.Fatalf("asserted missing_dkim while selector s1 was unresolved")
		}
	}
	if !slices.Contains(res.Indeterminate, checks.Key{IssueType: IssueDKIMMissing}) {
		t.Fatalf("missing_dkim not protected; Indeterminate = %+v", res.Indeterminate)
	}
}

func TestDKIMFoundRecordResolvesMissingKey(t *testing.T) {
	d := emailDetector()
	res, err := d.Detect(EmailSecurityEvidence{
		HandlesEmail: true,
		DKIMSelectors: []DKIMSelectorEvidence{
			{
				Selector: "google",
				Status:   ResolutionData,
				Records:  []string{"v=DKIM1; k=rsa; p=" + strings.Repeat("A", 300)},
			},
			{Selector: "s1", Status: ResolutionIndeterminate},
		},
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if slices.Contains(res.Indeterminate, checks.Key{IssueType: IssueDKIMMissing}) {
		t.Fatalf("missing_dkim protected despite a valid DKIM record being found")
	}
}

func TestEmailPresenceLookupsProtectKeys(t *testing.T) {
	d := emailDetector()
	res, err := d.Detect(EmailSecurityEvidence{
		HandlesEmail: true,
		DMARCStatus:  ResolutionEmpty,
		BIMIStatus:   ResolutionIndeterminate,
		MTASTSStatus: ResolutionIndeterminate,
		TLSRPTStatus: ResolutionIndeterminate,
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := []checks.Key{
		{IssueType: IssueBIMIRequiresDMARC},
		{IssueType: IssueBIMIInvalidLogo},
		{IssueType: IssueBIMIInvalidVMC},
		{IssueType: IssueMTASTSPolicyUnreachable},
		{IssueType: IssueMTASTSModeNotEnforcing},
		{IssueType: IssueMTASTSMXMismatch},
		{IssueType: IssueMTASTSShortMaxAge},
		{IssueType: IssueTLSRPTInvalidRua},
	}
	for _, k := range want {
		if !slices.Contains(res.Indeterminate, k) {
			t.Errorf("%s not protected; Indeterminate = %+v", k.IssueType, res.Indeterminate)
		}
	}
}

func TestMTASTSUnfetchedPolicyProtectsContentKeys(t *testing.T) {
	d := emailDetector()
	contentKeys := []checks.Key{
		{IssueType: IssueMTASTSModeNotEnforcing},
		{IssueType: IssueMTASTSMXMismatch},
		{IssueType: IssueMTASTSShortMaxAge},
	}

	unfetched, err := d.Detect(EmailSecurityEvidence{
		HandlesEmail: true, MTASTSStatus: ResolutionData, MTASTSConfigured: true,
		MTASTSPolicyReached: false,
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if issueSet(unfetched.Found) == nil {
		t.Fatalf("an unfetchable policy should still report policy_unreachable")
	}
	for _, k := range contentKeys {
		if !slices.Contains(unfetched.Indeterminate, k) {
			t.Errorf("%s not protected on an unfetched policy; Indeterminate = %+v",
				k.IssueType, unfetched.Indeterminate)
		}
	}

	fetched404, err := d.Detect(EmailSecurityEvidence{
		HandlesEmail: true, MTASTSStatus: ResolutionData, MTASTSConfigured: true,
		MTASTSPolicyReached: true, MTASTSPolicyStatus: 404,
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	for _, k := range contentKeys {
		if slices.Contains(fetched404.Indeterminate, k) {
			t.Errorf("%s protected despite an authoritative 404", k.IssueType)
		}
	}
}

func TestBIMIEnforcementUnknownOnIndeterminateDMARC(t *testing.T) {
	d := emailDetector()
	res, err := d.Detect(EmailSecurityEvidence{
		HandlesEmail: true,
		BIMIStatus:   ResolutionData,
		BIMIRecord:   "v=BIMI1; l=https://x/logo.svg",
		DMARCStatus:  ResolutionIndeterminate,
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	for _, f := range res.Found {
		if f.IssueType == IssueBIMIRequiresDMARC {
			t.Fatalf("asserted %s while the DMARC verdict was unknown", f.IssueType)
		}
	}
	if !slices.Contains(res.Indeterminate, checks.Key{IssueType: IssueBIMIRequiresDMARC}) {
		t.Fatalf("bimi_requires_enforced_dmarc not protected; Indeterminate = %+v",
			res.Indeterminate)
	}
}

func TestCNAMEChainIndeterminateProtectsChainKeys(t *testing.T) {
	d := CNAMEDetector{LongChainThreshold: 8}
	res, err := d.Detect(CNAMEEvidence{Targets: []CNAMETargetEvidence{{
		Target:           "a.example.com",
		ResolutionStatus: ResolutionData,
		ChainStatus:      ResolutionIndeterminate,
		ChainLength:      3,
	}}})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(res.Found) != 0 {
		t.Fatalf("truncated chain produced findings: %+v", res.Found)
	}
	for _, issue := range []string{IssueLongChain, IssueCNAMELoop} {
		want := checks.Key{IssueType: issue, EntityKey: "a.example.com"}
		if !slices.Contains(res.Indeterminate, want) {
			t.Errorf("%s not protected; Indeterminate = %+v", issue, res.Indeterminate)
		}
	}
}

func TestNameserverConsistencyNeedsTwoAnswers(t *testing.T) {
	d := nsHealthDetector()
	silent := func(ns string) NameserverProbeEvidence {
		p := healthyProbe(ns, "")
		p.ApexSerial = ""
		return p
	}
	res, err := d.Detect(NameserverHealthEvidence{
		RecordType: "SOA",
		Nameservers: []NameserverProbeEvidence{
			healthyProbe("ns1.example.com", "2026072201"),
			silent("ns2.example.com"),
			silent("ns3.example.com"),
		},
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := checks.Key{IssueType: IssueNSResolverMismatch, EntityKey: "SOA"}
	if !slices.Contains(res.Indeterminate, want) {
		t.Fatalf("resolver_mismatch not protected on a single answer; Indeterminate = %+v",
			res.Indeterminate)
	}
}

func TestNameserverShedTCPProbeProtectsKey(t *testing.T) {
	d := nsHealthDetector()
	ns := healthyProbe("ns1.example.com", "2026072201")
	ns.TCPProbed, ns.TCPOK = false, false
	res, err := d.Detect(NameserverHealthEvidence{
		RecordType:  "SOA",
		Nameservers: []NameserverProbeEvidence{ns},
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	for _, f := range res.Found {
		if f.IssueType == IssueNSNoTCPSupport {
			t.Fatalf("asserted no_tcp_support for an unattempted TCP probe")
		}
	}
	want := checks.Key{IssueType: IssueNSNoTCPSupport, EntityKey: "ns1.example.com"}
	if !slices.Contains(res.Indeterminate, want) {
		t.Fatalf("no_tcp_support not protected; Indeterminate = %+v", res.Indeterminate)
	}
}

func TestNameserverConsistencyNeedsEveryNameserver(t *testing.T) {
	d := nsHealthDetector()
	silent := healthyProbe("ns3.example.com", "")
	silent.ApexSerial = ""
	res, err := d.Detect(NameserverHealthEvidence{
		RecordType: "SOA",
		Nameservers: []NameserverProbeEvidence{
			healthyProbe("ns1.example.com", "2026072201"),
			healthyProbe("ns2.example.com", "2026072201"),
			silent,
		},
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := checks.Key{IssueType: IssueNSResolverMismatch, EntityKey: "SOA"}
	if !slices.Contains(res.Indeterminate, want) {
		t.Fatalf("resolver_mismatch resolved while ns3 was silent; Indeterminate = %+v",
			res.Indeterminate)
	}
}

func TestNameserverConsistencyFullSetIsDeterminate(t *testing.T) {
	d := nsHealthDetector()
	res, err := d.Detect(NameserverHealthEvidence{
		RecordType: "SOA",
		Nameservers: []NameserverProbeEvidence{
			healthyProbe("ns1.example.com", "2026072201"),
			healthyProbe("ns2.example.com", "2026072201"),
		},
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := checks.Key{IssueType: IssueNSResolverMismatch, EntityKey: "SOA"}
	if slices.Contains(res.Indeterminate, want) {
		t.Fatalf("resolver_mismatch protected despite a complete, agreeing answer set")
	}
}

func TestCNAMEChainIndeterminateProtectsUnassertedKey(t *testing.T) {
	d := CNAMEDetector{LongChainThreshold: 8}
	res, err := d.Detect(CNAMEEvidence{Targets: []CNAMETargetEvidence{{
		Target:           "a.example.com",
		ResolutionStatus: ResolutionData,
		ChainStatus:      ResolutionIndeterminate,
		ChainLength:      9,
	}}})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if issueSet(res.Found)[0] != IssueLongChain {
		t.Fatalf("expected long_chain to still be asserted, got %v", issueSet(res.Found))
	}
	loop := checks.Key{IssueType: IssueCNAMELoop, EntityKey: "a.example.com"}
	if !slices.Contains(res.Indeterminate, loop) {
		t.Fatalf("cname_loop not protected alongside an asserted long_chain; Indeterminate = %+v",
			res.Indeterminate)
	}
	if slices.Contains(
		res.Indeterminate,
		checks.Key{IssueType: IssueLongChain, EntityKey: "a.example.com"},
	) {
		t.Fatalf("long_chain both asserted and protected")
	}
}

func TestNameserverConsistencySingleNameserverIsDeterminate(t *testing.T) {
	d := nsHealthDetector()
	res, err := d.Detect(NameserverHealthEvidence{
		RecordType: "SOA",
		Nameservers: []NameserverProbeEvidence{
			healthyProbe("ns1.example.com", "2026072201"),
		},
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	want := checks.Key{IssueType: IssueNSResolverMismatch, EntityKey: "SOA"}
	if slices.Contains(res.Indeterminate, want) {
		t.Fatalf("resolver_mismatch protected for a single-nameserver domain")
	}
}
