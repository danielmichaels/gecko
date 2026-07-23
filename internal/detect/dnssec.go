package detect

import (
	"strings"

	"github.com/danielmichaels/gecko/internal/checks"
)

const CheckDNSSEC = "dnssec"

const (
	IssueDNSSECBrokenChain   = "dnssec_broken_chain"
	IssueDNSSECWeakAlgorithm = "dnssec_weak_algorithm"
)

// deprecatedDNSSECAlgorithms maps DNSSEC algorithm numbers RFC 8624 deprecates to
// their names.
var deprecatedDNSSECAlgorithms = map[string]string{
	"1": "RSAMD5",
	"3": "DSA",
	"5": "RSASHA1",
	"6": "DSA-NSEC3-SHA1",
	"7": "RSASHA1-NSEC3-SHA1",
}

// DNSSECEvidence is the collected DNSSEC scan state for one asset. Fetched
// separates "no scan result" (unknown) from a real result; NotApplicable marks a
// non-apex name where DNSSEC does not apply. Both short-circuit the detector.
type DNSSECEvidence struct {
	ValidationError string   `json:"validation_error"`
	Algorithms      []string `json:"algorithms"`
	Fetched         bool     `json:"fetched"`
	NotApplicable   bool     `json:"not_applicable"`
	HasDNSKEY       bool     `json:"has_dnskey"`
	HasDS           bool     `json:"has_ds"`
	HasRRSIG        bool     `json:"has_rrsig"`
}

type DNSSECDetector struct{}

func (DNSSECDetector) Kind() string                { return CheckDNSSEC }
func (DNSSECDetector) Scope() checks.EvidenceScope { return checks.SingleAsset }

// Detect judges DNSSEC deployment. A fully-signed zone (all of DNSKEY/DS/RRSIG)
// and an unsigned zone are both compliant states that yield nothing; only a broken
// chain (validation failure or partial deployment) or a deprecated algorithm on an
// otherwise-signed zone is a finding.
func (DNSSECDetector) Detect(ev DNSSECEvidence) (checks.DetectResult, error) {
	if !ev.Fetched || ev.NotApplicable {
		return checks.DetectResult{}, nil
	}
	var out []checks.Finding
	switch {
	case ev.ValidationError != "":
		out = append(out, checks.Finding{
			IssueType: IssueDNSSECBrokenChain,
			Severity:  "high",
			Title:     "DNSSEC validation failed",
			Details:   "DNSSEC validation failed: " + ev.ValidationError,
		})
	case !ev.HasDNSKEY && !ev.HasDS && !ev.HasRRSIG:
		// DNSSEC not enabled -- compliant, no finding.
	case ev.HasDNSKEY && ev.HasDS && ev.HasRRSIG:
		// Fully signed -- compliant, but a deprecated algorithm is still a problem.
		if names := deprecatedAlgorithmNames(ev.Algorithms); len(names) > 0 {
			out = append(out, checks.Finding{
				IssueType: IssueDNSSECWeakAlgorithm,
				Severity:  "medium",
				Title:     "Deprecated DNSSEC signing algorithm",
				Details: "DNSSEC uses deprecated signing algorithm(s): " + strings.Join(
					names,
					", ",
				),
			})
		}
	default:
		out = append(out, checks.Finding{
			IssueType: IssueDNSSECBrokenChain,
			Severity:  "high",
			Title:     "DNSSEC partially deployed",
			Details:   "DNSSEC is partially deployed: missing DNSKEY, DS, or RRSIG records",
		})
	}
	return checks.DetectResult{Found: out}, nil
}

// deprecatedAlgorithmNames returns the names of any deprecated signing algorithms
// present, trimming whitespace on each input value.
func deprecatedAlgorithmNames(algorithms []string) []string {
	var names []string
	for _, a := range algorithms {
		if name, ok := deprecatedDNSSECAlgorithms[strings.TrimSpace(a)]; ok {
			names = append(names, name)
		}
	}
	return names
}
