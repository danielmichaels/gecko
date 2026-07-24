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

var deprecatedDNSSECAlgorithms = map[string]string{
	"1": "RSAMD5",
	"3": "DSA",
	"5": "RSASHA1",
	"6": "DSA-NSEC3-SHA1",
	"7": "RSASHA1-NSEC3-SHA1",
}

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
	case ev.HasDNSKEY && ev.HasDS && ev.HasRRSIG:
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

func deprecatedAlgorithmNames(algorithms []string) []string {
	var names []string
	for _, a := range algorithms {
		if name, ok := deprecatedDNSSECAlgorithms[strings.TrimSpace(a)]; ok {
			names = append(names, name)
		}
	}
	return names
}
