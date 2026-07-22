package detect

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/checks"
)

const CheckNameserverHealth = "nameserver_health"

const (
	IssueNSUnreachable      = "unreachable"
	IssueNSNoTCPSupport     = "no_tcp_support"
	IssueNSNoEDNSSupport    = "no_edns_support"
	IssueNSHighLatency      = "high_latency"
	IssueNSResolverMismatch = "resolver_mismatch"
)

// NameserverProbeEvidence is one authoritative nameserver's direct-probe outcome.
// Probed/TCPProbed record whether the exchange was actually attempted (the fleet
// rate limiter may have denied it) so a denied probe is never read as a genuine
// failure. LatencyMs/ApexSerial are only meaningful when Reached.
type NameserverProbeEvidence struct {
	Nameserver string `json:"nameserver"`
	ApexSerial string `json:"apex_serial"`
	LatencyMs  int32  `json:"latency_ms"`
	Probed     bool   `json:"probed"`
	Reached    bool   `json:"reached"`
	TCPProbed  bool   `json:"tcp_probed"`
	TCPOK      bool   `json:"tcp_ok"`
	HasEDNS    bool   `json:"has_edns"`
}

// NameserverHealthEvidence is one domain's authoritative-NS-set probe results for
// the zone apex SOA. RecordType keys the latency/consistency findings ("SOA").
type NameserverHealthEvidence struct {
	RecordType  string                    `json:"record_type"`
	Nameservers []NameserverProbeEvidence `json:"nameservers"`
}

// NameserverHealthDetector judges reachability, TCP/EDNS support, response latency,
// and cross-nameserver apex-SOA agreement. Latency thresholds are injected.
type NameserverHealthDetector struct {
	LatencyInfoMs   int32
	LatencyLowMs    int32
	LatencyMediumMs int32
}

func (NameserverHealthDetector) Kind() string                { return CheckNameserverHealth }
func (NameserverHealthDetector) Scope() checks.EvidenceScope { return checks.SingleAsset }

func (d NameserverHealthDetector) Detect(ev NameserverHealthEvidence) ([]checks.Finding, error) {
	var out []checks.Finding
	for _, ns := range ev.Nameservers {
		if ns.Probed && !ns.Reached {
			out = append(out, checks.Finding{
				IssueType: IssueNSUnreachable,
				EntityKey: ns.Nameserver,
				Severity:  "high",
				Title:     "Nameserver is unreachable",
				Details:   "Nameserver did not answer a direct UDP query (unreachable or timing out)",
			})
		}
		if ns.Reached && ns.TCPProbed && !ns.TCPOK {
			out = append(out, checks.Finding{
				IssueType: IssueNSNoTCPSupport,
				EntityKey: ns.Nameserver,
				Severity:  "medium",
				Title:     "Nameserver doesn't answer over TCP",
				Details:   "Nameserver does not answer over TCP, which is required for large responses and DNSSEC",
			})
		}
		if ns.Reached && !ns.HasEDNS {
			out = append(out, checks.Finding{
				IssueType: IssueNSNoEDNSSupport,
				EntityKey: ns.Nameserver,
				Severity:  "info",
				Title:     "Nameserver doesn't support EDNS0",
				Details:   "Nameserver does not support EDNS0, limiting modern DNS features and UDP payload size",
			})
		}
		if ns.Reached {
			if sev, threshold, ok := d.latencyTier(ns.LatencyMs); ok {
				out = append(out, checks.Finding{
					IssueType: IssueNSHighLatency,
					EntityKey: ns.Nameserver + "|" + ev.RecordType,
					Severity:  sev,
					Title:     "Nameserver response is slow",
					Details:   fmt.Sprintf("Nameserver responded in %dms (exceeds %dms)", ns.LatencyMs, threshold),
				})
			}
		}
	}

	if f, ok := d.consistencyFinding(ev); ok {
		out = append(out, f)
	}
	return out, nil
}

// latencyTier maps a latency onto its exceeded threshold tier, or ok=false when
// under the info floor (compliant, no finding).
func (d NameserverHealthDetector) latencyTier(ms int32) (severity string, threshold int32, ok bool) {
	switch {
	case ms >= d.LatencyMediumMs:
		return "medium", d.LatencyMediumMs, true
	case ms >= d.LatencyLowMs:
		return "low", d.LatencyLowMs, true
	case ms >= d.LatencyInfoMs:
		return "info", d.LatencyInfoMs, true
	default:
		return "", 0, false
	}
}

type nsAnswer struct {
	nameserver string
	serial     string
}

// consistencyFinding flags divergent apex SOA serials across the reachable
// nameservers. Kept low severity and worded as possibly-transient: this check has
// no cross-scan memory, so propagation lag is not escalated.
func (d NameserverHealthDetector) consistencyFinding(ev NameserverHealthEvidence) (checks.Finding, bool) {
	var answers []nsAnswer
	for _, ns := range ev.Nameservers {
		if ns.Reached && ns.ApexSerial != "" {
			answers = append(answers, nsAnswer{ns.Nameserver, ns.ApexSerial})
		}
	}
	if len(answers) == 0 {
		return checks.Finding{}, false
	}
	var divergentNS, divergentSerial string
	for _, a := range answers[1:] {
		if a.serial != answers[0].serial {
			divergentNS, divergentSerial = a.nameserver, a.serial
			break
		}
	}
	if divergentNS == "" {
		return checks.Finding{}, false
	}
	evJSON, _ := json.Marshal(map[string]any{
		"resolver1": answers[0].nameserver, "resolver1_result": answers[0].serial,
		"resolver2": divergentNS, "resolver2_result": divergentSerial,
	})
	return checks.Finding{
		IssueType: IssueNSResolverMismatch,
		EntityKey: ev.RecordType,
		Severity:  "low",
		Title:     "Nameservers return divergent answers",
		Details: "Authoritative nameservers return divergent apex SOA records (may be transient propagation): " +
			summarizeSerials(answers),
		Evidence: evJSON,
	}, true
}

func summarizeSerials(answers []nsAnswer) string {
	parts := make([]string, 0, len(answers))
	for _, a := range answers {
		parts = append(parts, fmt.Sprintf("%s=%q", a.nameserver, a.serial))
	}
	return strings.Join(parts, ", ")
}
