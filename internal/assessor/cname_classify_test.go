package assessor

import (
	"testing"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/store"
)

func TestClassifyDangling(t *testing.T) {
	takeoverFP := cnameFingerprint{
		Suffix:           ".s3.amazonaws.com",
		Provider:         "AWS S3",
		ErrorBody:        "NoSuchBucket",
		TakeoverPossible: true,
	}
	benignFP := cnameFingerprint{
		Suffix:           ".myshopify.com",
		Provider:         "Shopify",
		TakeoverPossible: false,
	}

	tests := []struct {
		name         string
		res          dnsclient.ResolutionStatus
		fp           cnameFingerprint
		fpMatched    bool
		probe        ProbeResult
		wantFinding  bool
		wantSeverity store.FindingSeverity
		wantTakeover bool
		wantProvider string
	}{
		{
			name:      "takeover provider with confirmed error body is high takeover",
			res:       dnsclient.ResolutionData,
			fp:        takeoverFP,
			fpMatched: true,
			probe: ProbeResult{
				Reached:    true,
				StatusCode: 404,
				Body:       "<Error>NoSuchBucket</Error>",
			},
			wantFinding:  true,
			wantSeverity: store.FindingSeverityHigh,
			wantTakeover: true,
			wantProvider: "AWS S3",
		},
		{
			name:         "takeover provider that does not resolve is high takeover",
			res:          dnsclient.ResolutionEmpty,
			fp:           takeoverFP,
			fpMatched:    true,
			probe:        ProbeResult{Reached: false},
			wantFinding:  true,
			wantSeverity: store.FindingSeverityHigh,
			wantTakeover: true,
			wantProvider: "AWS S3",
		},
		{
			name:        "takeover provider serving a live page is suppressed",
			res:         dnsclient.ResolutionData,
			fp:          takeoverFP,
			fpMatched:   true,
			probe:       ProbeResult{Reached: true, StatusCode: 200, Body: "<html>welcome</html>"},
			wantFinding: false,
		},
		{
			name:         "non-resolving target without fingerprint is medium not takeover",
			res:          dnsclient.ResolutionEmpty,
			fpMatched:    false,
			wantFinding:  true,
			wantSeverity: store.FindingSeverityMedium,
			wantTakeover: false,
		},
		{
			name:         "non-resolving benign provider is medium with provider, not takeover",
			res:          dnsclient.ResolutionEmpty,
			fp:           benignFP,
			fpMatched:    true,
			wantFinding:  true,
			wantSeverity: store.FindingSeverityMedium,
			wantTakeover: false,
			wantProvider: "Shopify",
		},
		{
			name:        "healthy resolving target without fingerprint yields no finding",
			res:         dnsclient.ResolutionData,
			fpMatched:   false,
			wantFinding: false,
		},
		{
			name:        "indeterminate resolution is not acted on",
			res:         dnsclient.ResolutionIndeterminate,
			fpMatched:   false,
			wantFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyDangling(tt.res, tt.fp, tt.fpMatched, tt.probe)
			if got.finding != tt.wantFinding {
				t.Fatalf("finding: got=%v want=%v", got.finding, tt.wantFinding)
			}
			if !tt.wantFinding {
				return
			}
			if got.severity != tt.wantSeverity {
				t.Errorf("severity: got=%s want=%s", got.severity, tt.wantSeverity)
			}
			if got.takeoverPossible != tt.wantTakeover {
				t.Errorf("takeover: got=%v want=%v", got.takeoverPossible, tt.wantTakeover)
			}
			if got.provider != tt.wantProvider {
				t.Errorf("provider: got=%q want=%q", got.provider, tt.wantProvider)
			}
			if got.status != store.FindingStatusOpen {
				t.Errorf("status: got=%s want=open", got.status)
			}
		})
	}
}
