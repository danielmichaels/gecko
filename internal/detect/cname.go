package detect

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/checks"
)

const CheckCNAME = "cname"

const (
	IssueDanglingCNAME = "dangling_cname"
	IssuePointsToIP    = "points_to_ip"
	IssueLongChain     = "long_chain"
	IssueCNAMELoop     = "cname_loop"
)

// Resolution outcomes as carried in evidence (dnsclient.ResolutionStatus, stringified
// at collect time so the detector stays free of the dnsclient type).
const (
	ResolutionData          = "data"
	ResolutionEmpty         = "empty"
	ResolutionIndeterminate = "indeterminate"
)

// CNAMETargetEvidence is the collected state for one CNAME target.
type CNAMETargetEvidence struct {
	Target           string `json:"target"`
	ResolutionStatus string `json:"resolution_status"`
	// ChainStatus marks incomplete length and loop observations.
	ChainStatus      string `json:"chain_status"`
	Provider         string `json:"provider"`
	FPErrorBody      string `json:"fp_error_body"`
	ProbeBody        string `json:"probe_body"`
	ProbeStatusCode  int    `json:"probe_status_code"`
	ChainLength      int    `json:"chain_length"`
	FPMatched        bool   `json:"fp_matched"`
	TakeoverProvider bool   `json:"takeover_provider"`
	ProbeReached     bool   `json:"probe_reached"`
	IsIPLiteral      bool   `json:"is_ip_literal"`
	ChainLooped      bool   `json:"chain_looped"`
}

type CNAMEEvidence struct {
	Targets []CNAMETargetEvidence `json:"targets"`
}

// CNAMEDetector flags dangling/takeover-able CNAME targets and chain-hygiene issues
// (IP-literal target, loop, over-long chain). LongChainThreshold is injected.
type CNAMEDetector struct {
	LongChainThreshold int
}

func (CNAMEDetector) Kind() string                { return CheckCNAME }
func (CNAMEDetector) Scope() checks.EvidenceScope { return checks.SingleAsset }

func (d CNAMEDetector) Detect(ev CNAMEEvidence) (checks.DetectResult, error) {
	var res checks.DetectResult
	for _, t := range ev.Targets {
		if f, ok := danglingFinding(t); ok {
			res.Found = append(res.Found, f)
		} else if t.ResolutionStatus == ResolutionIndeterminate {
			// A failed lookup cannot assert or clear a dangling finding.
			res.Indeterminate = append(res.Indeterminate,
				checks.Key{IssueType: IssueDanglingCNAME, EntityKey: t.Target})
		}
		f, found := d.chainFinding(t)
		if found {
			res.Found = append(res.Found, f)
		}
		if t.ChainStatus == ResolutionIndeterminate {
			// An incomplete walk cannot clear an unasserted chain finding.
			for _, issue := range []string{IssueLongChain, IssueCNAMELoop} {
				if found && f.IssueType == issue {
					continue
				}
				res.Indeterminate = append(res.Indeterminate,
					checks.Key{IssueType: issue, EntityKey: t.Target})
			}
		}
	}
	return res, nil
}

// danglingFinding requires confirmed evidence for provider-specific takeovers.
func danglingFinding(t CNAMETargetEvidence) (checks.Finding, bool) {
	if t.ResolutionStatus == ResolutionIndeterminate {
		return checks.Finding{}, false
	}
	nonResolving := t.ResolutionStatus == ResolutionEmpty

	if t.FPMatched && t.TakeoverProvider {
		bodyConfirmed := t.ProbeReached && t.FPErrorBody != "" &&
			strings.Contains(t.ProbeBody, t.FPErrorBody)
		switch {
		case bodyConfirmed || nonResolving:
			return danglingF(t.Target, "high", t.Provider, true, fmt.Sprintf(
				"CNAME target points to %s and the resource appears unclaimed (subdomain takeover candidate)",
				t.Provider,
			)), true
		case t.ProbeReached && t.ProbeStatusCode == 200:
			return checks.Finding{}, false
		default:
			return danglingF(t.Target, "medium", t.Provider, false, fmt.Sprintf(
				"CNAME target points to %s; takeover could not be confirmed", t.Provider,
			)), true
		}
	}

	if nonResolving {
		provider := ""
		if t.FPMatched {
			provider = t.Provider
		}
		return danglingF(t.Target, "medium", provider, false,
			"CNAME target does not resolve (NXDOMAIN)"), true
	}

	return checks.Finding{}, false
}

func danglingF(target, severity, provider string, takeover bool, details string) checks.Finding {
	ev, _ := json.Marshal(map[string]any{
		"target_domain":     target,
		"service_provider":  provider,
		"takeover_possible": takeover,
	})
	return checks.Finding{
		IssueType: IssueDanglingCNAME,
		EntityKey: target,
		Severity:  severity,
		Title:     "Dangling CNAME",
		Details:   details,
		Evidence:  ev,
	}
}

// chainFinding classifies one target's chain hygiene: an IP-literal target, a loop,
// or an over-long chain. At most one applies, checked in that priority order.
func (d CNAMEDetector) chainFinding(t CNAMETargetEvidence) (checks.Finding, bool) {
	switch {
	case t.IsIPLiteral:
		return checks.Finding{
			IssueType: IssuePointsToIP,
			EntityKey: t.Target,
			Severity:  "medium",
			Title:     "CNAME points to an IP address",
			Details: fmt.Sprintf(
				"CNAME target %q is an IP address; a CNAME must point to a name",
				strings.TrimSuffix(t.Target, "."),
			),
		}, true
	case t.ChainLooped:
		return checks.Finding{
			IssueType: IssueCNAMELoop,
			EntityKey: t.Target,
			Severity:  "medium",
			Title:     "CNAME chain forms a loop",
			Details:   "CNAME chain forms a loop",
		}, true
	case t.ChainLength >= d.LongChainThreshold:
		return checks.Finding{
			IssueType: IssueLongChain,
			EntityKey: t.Target,
			Severity:  "low",
			Title:     "CNAME chain too long",
			Details:   fmt.Sprintf("CNAME chain is %d hops long", t.ChainLength),
		}, true
	}
	return checks.Finding{}, false
}
