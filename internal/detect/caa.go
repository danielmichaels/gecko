package detect

import (
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/checks"
)

const CheckCAA = "caa"

const (
	IssueCAAMissing             = "caa_missing"
	IssueCAAAllowsAnyCA         = "caa_allows_any_ca"
	IssueCAAUntrustedIssuer     = "caa_untrusted_issuer"
	IssueCAAUnknownCriticalFlag = "caa_unknown_critical_flag"
	IssueCAAConflictingRecords  = "caa_conflicting_records"
	IssueCAARequiredForCert     = "caa_required_for_cert"
	IssueCAAMissingIodef        = "missing_iodef"
)

const caaCriticalFlag = 128

// defaultTrustedCAs is the built-in allowlist of CAA issuer identifiers for
// well-known public CAs; an issuer outside it is a low-severity review finding.
var defaultTrustedCAs = map[string]struct{}{
	"letsencrypt.org": {}, "digicert.com": {}, "sectigo.com": {}, "comodoca.com": {},
	"globalsign.com": {}, "google.com": {}, "pki.goog": {}, "amazon.com": {},
	"amazonaws.com": {}, "amazontrust.com": {}, "awstrust.com": {}, "godaddy.com": {},
	"ssl.com": {}, "entrust.net": {}, "buypass.com": {}, "actalis.it": {},
	"certainly.com": {}, "microsoft.com": {},
}

// CAARecord is one collected CAA property.
type CAARecord struct {
	Tag   string `json:"tag"`
	Value string `json:"value"`
	Flags int32  `json:"flags"`
}

// CAAEvidence is the collected CAA state. LookedUp separates a failed lookup
// (unknown) from an authoritative result; an authoritative empty RRset (LookedUp
// with no Records) is itself a finding. HasCert gates the cert-related findings.
type CAAEvidence struct {
	Records  []CAARecord `json:"records"`
	LookedUp bool        `json:"looked_up"`
	HasCert  bool        `json:"has_cert"`
}

type CAADetector struct{}

func (CAADetector) Kind() string                { return CheckCAA }
func (CAADetector) Scope() checks.EvidenceScope { return checks.SingleAsset }

func (CAADetector) Detect(ev CAAEvidence) ([]checks.Finding, error) {
	if !ev.LookedUp {
		return nil, nil
	}
	if len(ev.Records) == 0 {
		return caaMissingFindings(ev.HasCert), nil
	}
	return caaPresentFindings(ev), nil
}

func caaMissingFindings(hasCert bool) []checks.Finding {
	sev := "info"
	if hasCert {
		sev = "low"
	}
	out := []checks.Finding{{
		IssueType: IssueCAAMissing,
		Severity:  sev,
		Title:     "No CAA records published",
		Details:   "No CAA records are published at the domain apex",
	}}
	if hasCert {
		out = append(out, checks.Finding{
			IssueType: IssueCAARequiredForCert,
			Severity:  "low",
			Title:     "CAA required for cert-bearing domain",
			Details:   "Domain serves a certificate but publishes no CAA policy restricting issuance",
		})
	}
	return out
}

// caaPresentFindings emits only the problems; every compliant branch (records
// present, issue restricted, trusted issuers, iodef present, ...) is absence.
func caaPresentFindings(ev CAAEvidence) []checks.Finding {
	c := classifyCAA(ev.Records)
	var out []checks.Finding
	if !c.hasIssueTag {
		out = append(out, checks.Finding{
			IssueType: IssueCAAAllowsAnyCA,
			Severity:  "low",
			Title:     "CAA allows any CA to issue",
			Details:   "CAA records exist but contain no issue property, so any CA may issue certificates",
		})
	}
	if c.sawIssuer && len(c.untrusted) > 0 {
		out = append(out, checks.Finding{
			IssueType: IssueCAAUntrustedIssuer,
			Severity:  "low",
			Title:     "CAA authorises untrusted issuer",
			Details:   fmt.Sprintf("CAA authorises issuance by unrecognised CA(s): %s", strings.Join(c.untrusted, ", ")),
		})
	}
	if c.hasUnknownCritical {
		out = append(out, checks.Finding{
			IssueType: IssueCAAUnknownCriticalFlag,
			Severity:  "medium",
			Title:     "Unknown critical CAA property",
			Details:   "A CAA property gecko does not recognise has the critical flag set; conformant CAs must refuse issuance",
		})
	}
	if c.hasNoIssuance && c.hasPermissiveIssue {
		out = append(out, checks.Finding{
			IssueType: IssueCAAConflictingRecords,
			Severity:  "medium",
			Title:     "Conflicting CAA records",
			Details:   "CAA contains a no-issuance directive (issue \";\") alongside a permissive issue property",
		})
	}
	if !c.hasIodef {
		out = append(out, checks.Finding{
			IssueType: IssueCAAMissingIodef,
			Severity:  "info",
			Title:     "Missing iodef reporting endpoint",
			Details:   "CAA does not publish an iodef property for violation reporting",
		})
	}
	return out
}

type caaClass struct {
	untrusted          []string
	hasIssueTag        bool
	hasIodef           bool
	hasUnknownCritical bool
	hasNoIssuance      bool
	hasPermissiveIssue bool
	sawIssuer          bool
}

// classifyCAA derives the policy booleans. Only an `issue` property (not
// `issuewild`) drives the any-CA / conflicting-policy signals; `issuewild` values
// still contribute their issuer to the trusted-CA check.
func classifyCAA(records []CAARecord) caaClass {
	var c caaClass
	for _, r := range records {
		switch strings.ToLower(strings.TrimSpace(r.Tag)) {
		case "issue", "issuewild":
			isIssue := strings.EqualFold(strings.TrimSpace(r.Tag), "issue")
			if isIssue {
				c.hasIssueTag = true
			}
			ca := caaIssuerDomain(r.Value)
			if ca == "" {
				if isIssue {
					c.hasNoIssuance = true
				}
				continue
			}
			c.sawIssuer = true
			if isIssue {
				c.hasPermissiveIssue = true
			}
			if !isTrustedCA(ca) {
				c.untrusted = append(c.untrusted, ca)
			}
		case "iodef":
			c.hasIodef = true
		default:
			if r.Flags&caaCriticalFlag != 0 {
				c.hasUnknownCritical = true
			}
		}
	}
	return c
}

// caaIssuerDomain extracts the CA identifier from an issue/issuewild value,
// dropping parameters after the first semicolon. An empty result denotes a
// no-issuance directive (e.g. `issue ";"`).
func caaIssuerDomain(value string) string {
	v := value
	if i := strings.Index(v, ";"); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.Trim(strings.TrimSpace(v), "\""))
}

func isTrustedCA(ca string) bool {
	_, ok := defaultTrustedCAs[ca]
	return ok
}
