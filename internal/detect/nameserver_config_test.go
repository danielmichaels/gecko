package detect

import (
	"sort"
	"testing"

	"github.com/danielmichaels/gecko/internal/checks"
)

func healthyNS(host string) NameserverEvidence {
	return NameserverEvidence{
		Host:        host,
		CNAMEStatus: ResolutionEmpty,
		AStatus:     ResolutionData,
		AAAAStatus:  ResolutionData,
		InBailiwick: false,
		ApexStatus:  ResolutionData,
	}
}

func nsConfigIssues(fs []checks.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.IssueType + "@" + f.EntityKey
	}
	sort.Strings(out)
	return out
}

func TestNameserverConfigDetect(t *testing.T) {
	d := NameserverConfigDetector{RecommendedCount: 2}

	t.Run("healthy two-provider set -> nothing", func(t *testing.T) {
		ev := NameserverConfigEvidence{DomainName: "example.com", Nameservers: []NameserverEvidence{
			healthyNS("ns1.provider-a.com"), healthyNS("ns1.provider-b.net"),
		}}
		got, _ := d.Detect(ev)
		if len(got) != 0 {
			t.Fatalf("got %v, want none", nsConfigIssues(got))
		}
	})

	t.Run("per-nameserver issues carry entity_key", func(t *testing.T) {
		cname := healthyNS("ns1.provider-a.com")
		cname.CNAMEStatus = ResolutionData
		unres := healthyNS("ns1.provider-b.net")
		unres.AStatus, unres.AAAAStatus = ResolutionEmpty, ResolutionEmpty
		dangling := healthyNS("ns1.sketchy.example")
		dangling.ApexStatus = ResolutionEmpty
		ev := NameserverConfigEvidence{DomainName: "example.com", Nameservers: []NameserverEvidence{cname, unres, dangling}}
		got := nsConfigIssues(mustDetect(t, d, ev))
		want := []string{
			IssueDanglingNS + "@ns1.sketchy.example",
			IssueNSIsCNAME + "@ns1.provider-a.com",
			IssueNSNotResolvable + "@ns1.provider-b.net",
		}
		sort.Strings(want)
		if !equalStrings(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("in-bailiwick nameserver is never dangling", func(t *testing.T) {
		ns := healthyNS("ns1.example.com")
		ns.InBailiwick = true
		ns.ApexStatus = ResolutionEmpty // would be dangling if judged
		ev := NameserverConfigEvidence{DomainName: "example.com", Nameservers: []NameserverEvidence{ns, healthyNS("ns2.provider-b.net")}}
		for _, f := range mustDetect(t, d, ev) {
			if f.IssueType == IssueDanglingNS {
				t.Fatalf("in-bailiwick NS wrongly flagged dangling")
			}
		}
	})

	t.Run("too few nameservers, no same_provider double-signal", func(t *testing.T) {
		ev := NameserverConfigEvidence{Nameservers: []NameserverEvidence{healthyNS("ns1.provider-a.com")}}
		got := nsConfigIssues(mustDetect(t, d, ev))
		want := []string{IssueInsufficientNameservers + "@"}
		if !equalStrings(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("same provider", func(t *testing.T) {
		ev := NameserverConfigEvidence{Nameservers: []NameserverEvidence{
			healthyNS("ns1.provider-a.com"), healthyNS("ns2.provider-a.com"),
		}}
		got := nsConfigIssues(mustDetect(t, d, ev))
		if !equalStrings(got, []string{IssueSameProvider + "@"}) {
			t.Fatalf("got %v, want same_provider", got)
		}
	})

	t.Run("no ipv6", func(t *testing.T) {
		a := healthyNS("ns1.provider-a.com")
		b := healthyNS("ns1.provider-b.net")
		a.AAAAStatus, b.AAAAStatus = ResolutionEmpty, ResolutionEmpty
		ev := NameserverConfigEvidence{Nameservers: []NameserverEvidence{a, b}}
		got := nsConfigIssues(mustDetect(t, d, ev))
		if !equalStrings(got, []string{IssueNoIPv6 + "@"}) {
			t.Fatalf("got %v, want no_ipv6", got)
		}
	})
}

func mustDetect(t *testing.T, d NameserverConfigDetector, ev NameserverConfigEvidence) []checks.Finding {
	t.Helper()
	got, err := d.Detect(ev)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
