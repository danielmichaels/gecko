package detect

import (
	"sort"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/checks"
)

func cnameDetector() CNAMEDetector { return CNAMEDetector{LongChainThreshold: 8} }

// target is a resolving, non-fingerprinted, short-chain baseline (no findings).
func target(name string) CNAMETargetEvidence {
	return CNAMETargetEvidence{Target: name, ResolutionStatus: ResolutionData, ChainLength: 1}
}

func danglingOf(fs []checks.Finding) *checks.Finding {
	for i := range fs {
		if fs[i].IssueType == IssueDanglingCNAME {
			return &fs[i]
		}
	}
	return nil
}

func TestCNAMEDanglingVerdict(t *testing.T) {
	d := cnameDetector()
	tests := []struct {
		name     string
		ev       CNAMETargetEvidence
		wantIT   string // "" means no dangling finding
		wantSev  string
		wantTake bool
	}{
		{
			name: "takeover provider + confirming body -> high takeover",
			ev: CNAMETargetEvidence{
				Target: "x.example.com", ResolutionStatus: ResolutionData,
				FPMatched: true, TakeoverProvider: true, Provider: "AWS S3",
				FPErrorBody: "NoSuchBucket", ProbeReached: true, ProbeStatusCode: 404,
				ProbeBody: "... NoSuchBucket ...", ChainLength: 1,
			},
			wantIT: IssueDanglingCNAME, wantSev: "high", wantTake: true,
		},
		{
			name: "takeover provider + non-resolving -> high takeover",
			ev: CNAMETargetEvidence{
				Target: "x.example.com", ResolutionStatus: ResolutionEmpty,
				FPMatched: true, TakeoverProvider: true, Provider: "GitHub Pages", ChainLength: 1,
			},
			wantIT: IssueDanglingCNAME, wantSev: "high", wantTake: true,
		},
		{
			name: "takeover provider but live 200 page -> suppressed",
			ev: CNAMETargetEvidence{
				Target: "x.example.com", ResolutionStatus: ResolutionData,
				FPMatched: true, TakeoverProvider: true, Provider: "AWS S3",
				FPErrorBody: "NoSuchBucket", ProbeReached: true, ProbeStatusCode: 200,
				ProbeBody: "welcome", ChainLength: 1,
			},
			wantIT: "",
		},
		{
			name: "takeover provider, resolves, unconfirmed -> medium",
			ev: CNAMETargetEvidence{
				Target: "x.example.com", ResolutionStatus: ResolutionData,
				FPMatched: true, TakeoverProvider: true, Provider: "Heroku",
				ProbeReached: true, ProbeStatusCode: 404, ChainLength: 1,
			},
			wantIT: IssueDanglingCNAME, wantSev: "medium", wantTake: false,
		},
		{
			name: "non-resolving, no takeover provider -> medium NXDOMAIN",
			ev: CNAMETargetEvidence{
				Target: "x.example.com", ResolutionStatus: ResolutionEmpty, ChainLength: 1,
			},
			wantIT: IssueDanglingCNAME, wantSev: "medium", wantTake: false,
		},
		{name: "clean resolution -> nothing", ev: target("x.example.com"), wantIT: ""},
		{
			name: "indeterminate resolution -> nothing (never act on SERVFAIL)",
			ev: CNAMETargetEvidence{
				Target: "x.example.com", ResolutionStatus: ResolutionIndeterminate, ChainLength: 1,
			},
			wantIT: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := d.Detect(CNAMEEvidence{Targets: []CNAMETargetEvidence{tt.ev}})
			f := danglingOf(got)
			if tt.wantIT == "" {
				if f != nil {
					t.Fatalf("expected no dangling finding, got %+v", *f)
				}
				return
			}
			if f == nil {
				t.Fatalf("expected dangling finding, got none (%d findings)", len(got))
			}
			if f.Severity != tt.wantSev {
				t.Errorf("severity = %q, want %q", f.Severity, tt.wantSev)
			}
			if f.EntityKey != tt.ev.Target {
				t.Errorf("entity_key = %q, want target %q", f.EntityKey, tt.ev.Target)
			}
			want := `"takeover_possible":true`
			if !tt.wantTake {
				want = `"takeover_possible":false`
			}
			if !strings.Contains(string(f.Evidence), want) {
				t.Errorf("evidence %q missing %q", f.Evidence, want)
			}
		})
	}
}

func TestCNAMEChainHygiene(t *testing.T) {
	d := cnameDetector()
	tests := []struct {
		name   string
		ev     CNAMETargetEvidence
		wantIT string
	}{
		{"ip literal", CNAMETargetEvidence{Target: "1.2.3.4", ResolutionStatus: ResolutionData, IsIPLiteral: true, ChainLength: 1}, IssuePointsToIP},
		{"loop", CNAMETargetEvidence{Target: "a.example.com", ResolutionStatus: ResolutionData, ChainLooped: true, ChainLength: 3}, IssueCNAMELoop},
		{"long chain", CNAMETargetEvidence{Target: "a.example.com", ResolutionStatus: ResolutionData, ChainLength: 9}, IssueLongChain},
		{"short chain -> nothing", target("a.example.com"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := d.Detect(CNAMEEvidence{Targets: []CNAMETargetEvidence{tt.ev}})
			var chainIT string
			for _, f := range got {
				switch f.IssueType {
				case IssuePointsToIP, IssueCNAMELoop, IssueLongChain:
					chainIT = f.IssueType
					if f.EntityKey != tt.ev.Target {
						t.Errorf("entity_key = %q, want %q", f.EntityKey, tt.ev.Target)
					}
				}
			}
			if chainIT != tt.wantIT {
				t.Fatalf("chain issue = %q, want %q", chainIT, tt.wantIT)
			}
		})
	}
}

func TestCNAMEMultipleTargets(t *testing.T) {
	d := cnameDetector()
	ev := CNAMEEvidence{Targets: []CNAMETargetEvidence{
		{Target: "a.example.com", ResolutionStatus: ResolutionEmpty, ChainLength: 1},
		{Target: "b.example.com", ResolutionStatus: ResolutionData, IsIPLiteral: true, ChainLength: 1},
		target("c.example.com"),
	}}
	got, _ := d.Detect(ev)
	var keys []string
	for _, f := range got {
		keys = append(keys, f.EntityKey+"/"+f.IssueType)
	}
	sort.Strings(keys)
	want := []string{"a.example.com/" + IssueDanglingCNAME, "b.example.com/" + IssuePointsToIP}
	if !equalStrings(keys, want) {
		t.Fatalf("findings = %v, want %v", keys, want)
	}
}
