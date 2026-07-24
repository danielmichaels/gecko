package detect

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/danielmichaels/gecko/internal/checks"
)

const CheckEmailSecurity = "email_security"

const (
	IssueSPFPermitAll        = "permit_all_spf_policy"
	IssueSPFWeakPolicy       = "weak_spf_policy"
	IssueSPFSoftFail         = "soft_fail_spf_policy"
	IssueSPFMissingMechanism = "missing_mechanisms"
	IssueSPFMissingAll       = "missing_all_mechanism"
	IssueSPFExcessiveLookups = "excessive_lookups"
	IssueSPFMissing          = "missing_spf"

	IssueDKIMWeakKey     = "weak_key_length"
	IssueDKIMTestMode    = "test_mode_enabled"
	IssueDKIMMissingTags = "missing_tags"
	IssueDKIMMissing     = "missing_dkim"

	IssueDMARCMissing     = "missing_dmarc"
	IssueDMARCWeakPolicy  = "weak_dmarc_policy"
	IssueDMARCQuarantine  = "quarantine_dmarc_policy"
	IssueDMARCReducedPct  = "dmarc_reduced_pct"
	IssueDMARCWeakSubPol  = "dmarc_weak_subdomain_policy"
	IssueDMARCMissingTags = "dmarc_missing_tags"

	IssueBIMIRequiresDMARC = "bimi_requires_enforced_dmarc"
	IssueBIMIInvalidLogo   = "bimi_invalid_logo"
	IssueBIMIInvalidVMC    = "bimi_invalid_vmc"

	IssueMTASTSPolicyUnreachable = "mta_sts_policy_unreachable"
	IssueMTASTSModeNotEnforcing  = "mta_sts_mode_not_enforcing"
	IssueMTASTSMXMismatch        = "mta_sts_mx_mismatch"
	IssueMTASTSShortMaxAge       = "mta_sts_short_max_age"

	IssueTLSRPTInvalidRua = "tls_rpt_invalid_rua"
)

var dmarcPrefix = regexp.MustCompile(`^v\s*=\s*DMARC1`)

type DKIMSelectorEvidence struct {
	Selector string   `json:"selector"`
	Status   string   `json:"status"`
	Records  []string `json:"records"`
}

type EmailSecurityEvidence struct {
	DMARCStatus          string                 `json:"dmarc_status"`
	BIMIStatus           string                 `json:"bimi_status"`
	MTASTSStatus         string                 `json:"mta_sts_status"`
	TLSRPTStatus         string                 `json:"tls_rpt_status"`
	BIMIRecord           string                 `json:"bimi_record"`
	MTASTSPolicyBody     string                 `json:"mta_sts_policy_body"`
	TLSRPTRecord         string                 `json:"tls_rpt_record"`
	SPFRecords           []string               `json:"spf_records"`
	DKIMSelectorsChecked []string               `json:"dkim_selectors_checked"`
	DKIMSelectors        []DKIMSelectorEvidence `json:"dkim_selectors"`
	DMARCRecords         []string               `json:"dmarc_records"`
	MXTargets            []string               `json:"mx_targets"`
	MTASTSPolicyStatus   int                    `json:"mta_sts_policy_status"`
	HandlesEmail         bool                   `json:"handles_email"`
	MTASTSConfigured     bool                   `json:"mta_sts_configured"`
	MTASTSPolicyReached  bool                   `json:"mta_sts_policy_reached"`
}

type EmailSecurityDetector struct {
	MaxSPFLookups    int
	MinDKIMKeyLength int
	MTASTSMinMaxAge  int
}

func (EmailSecurityDetector) Kind() string                { return CheckEmailSecurity }
func (EmailSecurityDetector) Scope() checks.EvidenceScope { return checks.SingleAsset }

func (d EmailSecurityDetector) Detect(ev EmailSecurityEvidence) (checks.DetectResult, error) {
	var res checks.DetectResult
	res.Found = append(res.Found, d.spfFindings(ev)...)
	res.Found = append(res.Found, d.dkimFindings(ev)...)
	res.Found = append(res.Found, dmarcFindings(ev)...)
	res.Found = append(res.Found, bimiFindings(ev)...)
	res.Found = append(res.Found, d.mtaStsFindings(ev)...)
	res.Found = append(res.Found, tlsRptFindings(ev)...)
	res.Indeterminate = emailIndeterminate(ev)
	return res, nil
}

func emailIndeterminate(ev EmailSecurityEvidence) []checks.Key {
	var keys []checks.Key

	if ev.DMARCStatus == ResolutionIndeterminate {
		keys = append(
			keys,
			checks.Key{IssueType: IssueDMARCMissing},
			checks.Key{IssueType: IssueDMARCWeakPolicy},
			checks.Key{IssueType: IssueDMARCQuarantine},
			checks.Key{IssueType: IssueDMARCReducedPct},
			checks.Key{IssueType: IssueDMARCWeakSubPol},
			checks.Key{IssueType: IssueDMARCMissingTags},
		)
	}

	if ev.HandlesEmail && !dkimAllDeterminate(ev) && !dkimHasValidRecord(ev) {
		keys = append(keys, checks.Key{IssueType: IssueDKIMMissing})
	}
	for _, sel := range ev.DKIMSelectors {
		if sel.Status == ResolutionIndeterminate {
			keys = append(
				keys,
				checks.Key{IssueType: IssueDKIMWeakKey, EntityKey: sel.Selector},
				checks.Key{IssueType: IssueDKIMTestMode, EntityKey: sel.Selector},
				checks.Key{IssueType: IssueDKIMMissingTags, EntityKey: sel.Selector},
			)
		}
	}

	if !ev.HandlesEmail {
		return keys
	}
	if ev.BIMIStatus == ResolutionIndeterminate {
		keys = append(
			keys,
			checks.Key{IssueType: IssueBIMIRequiresDMARC},
			checks.Key{IssueType: IssueBIMIInvalidLogo},
			checks.Key{IssueType: IssueBIMIInvalidVMC},
		)
	} else if ev.BIMIRecord != "" && ev.DMARCStatus == ResolutionIndeterminate {
		keys = append(keys, checks.Key{IssueType: IssueBIMIRequiresDMARC})
	}
	switch {
	case ev.MTASTSStatus == ResolutionIndeterminate:
		keys = append(
			keys,
			checks.Key{IssueType: IssueMTASTSPolicyUnreachable},
			checks.Key{IssueType: IssueMTASTSModeNotEnforcing},
			checks.Key{IssueType: IssueMTASTSMXMismatch},
			checks.Key{IssueType: IssueMTASTSShortMaxAge},
		)
	case ev.MTASTSConfigured && !ev.MTASTSPolicyReached:
		keys = append(
			keys,
			checks.Key{IssueType: IssueMTASTSModeNotEnforcing},
			checks.Key{IssueType: IssueMTASTSMXMismatch},
			checks.Key{IssueType: IssueMTASTSShortMaxAge},
		)
	}
	if ev.TLSRPTStatus == ResolutionIndeterminate {
		keys = append(keys, checks.Key{IssueType: IssueTLSRPTInvalidRua})
	}
	return keys
}

func dkimAllDeterminate(ev EmailSecurityEvidence) bool {
	for _, sel := range ev.DKIMSelectors {
		if sel.Status != ResolutionEmpty && sel.Status != ResolutionData {
			return false
		}
	}
	return len(ev.DKIMSelectors) > 0
}

func dkimHasValidRecord(ev EmailSecurityEvidence) bool {
	for _, sel := range ev.DKIMSelectors {
		for _, value := range sel.Records {
			if strings.Contains(value, "v=DKIM") {
				return true
			}
		}
	}
	return false
}

func ef(issueType, entityKey, severity, title, details string) checks.Finding {
	return checks.Finding{
		IssueType: issueType, EntityKey: entityKey, Severity: severity, Title: title, Details: details,
	}
}

func (d EmailSecurityDetector) spfFindings(ev EmailSecurityEvidence) []checks.Finding {
	if len(ev.SPFRecords) == 0 {
		if ev.HandlesEmail {
			return []checks.Finding{ef(IssueSPFMissing, "", "critical", "Missing SPF record",
				"No SPF record found for domain that handles email.")}
		}
		return nil
	}
	seen := map[string]bool{}
	var out []checks.Finding
	for _, value := range ev.SPFRecords {
		if f, ok := d.spfVerdict(value, ev.HandlesEmail); ok && !seen[f.IssueType] {
			seen[f.IssueType] = true
			out = append(out, f)
		}
	}
	return out
}

func (d EmailSecurityDetector) spfVerdict(v string, handlesEmail bool) (checks.Finding, bool) {
	switch {
	case spfPermitsAll(v):
		return ef(
			IssueSPFPermitAll,
			"",
			"critical",
			"SPF permits all senders",
			"SPF policy permits all senders ('+all'/'all'), allowing anyone to spoof the domain",
		), true
	case strings.Contains(v, " ?all"):
		return ef(IssueSPFWeakPolicy, "", "high", "SPF uses ?all",
			"SPF policy uses '?all' which is too permissive"), true
	case strings.Contains(v, " ~all"):
		return ef(IssueSPFSoftFail, "", "medium", "SPF uses ~all",
			"SPF policy uses '~all' (soft fail) instead of '-all' (hard fail)"), true
	case !strings.Contains(v, "include:") && !strings.Contains(v, "ip4:") && handlesEmail:
		return ef(IssueSPFMissingMechanism, "", "medium", "SPF missing mechanisms",
			"SPF record doesn't specify any IP ranges or include directives"), true
	case !strings.Contains(v, " all") && !strings.Contains(v, " -all") &&
		!strings.Contains(v, " ~all") && !strings.Contains(v, " ?all"):
		return ef(IssueSPFMissingAll, "", "high", "SPF missing 'all' mechanism",
			"SPF record does not end with an 'all' mechanism"), true
	case countSPFDNSLookups(v) > d.MaxSPFLookups:
		return ef(IssueSPFExcessiveLookups, "", "medium", "SPF exceeds lookup limit",
			fmt.Sprintf("SPF record requires %d DNS lookups, exceeding the RFC 7208 limit of %d",
				countSPFDNSLookups(v), d.MaxSPFLookups)), true
	default:
		return checks.Finding{}, false
	}
}

func spfPermitsAll(record string) bool {
	for _, tok := range strings.Fields(record) {
		if strings.EqualFold(tok, "all") || strings.EqualFold(tok, "+all") {
			return true
		}
	}
	return false
}

func countSPFDNSLookups(record string) int {
	count := 0
	for _, tok := range strings.Fields(record) {
		t := strings.ToLower(strings.TrimLeft(tok, "+-~?"))
		switch {
		case strings.HasPrefix(t, "include:"),
			strings.HasPrefix(t, "exists:"),
			strings.HasPrefix(t, "redirect="),
			t == "a", strings.HasPrefix(t, "a:"), strings.HasPrefix(t, "a/"),
			t == "mx", strings.HasPrefix(t, "mx:"), strings.HasPrefix(t, "mx/"),
			t == "ptr", strings.HasPrefix(t, "ptr:"):
			count++
		}
	}
	return count
}

func (d EmailSecurityDetector) dkimFindings(ev EmailSecurityEvidence) []checks.Finding {
	var out []checks.Finding
	for _, sel := range ev.DKIMSelectors {
		seen := map[string]bool{}
		for _, value := range sel.Records {
			if !strings.Contains(value, "v=DKIM") {
				continue
			}
			if strings.Contains(value, "k=rsa") && strings.Contains(value, "p=") &&
				len(extractKeyFromDKIM(value)) < d.MinDKIMKeyLength && !seen[IssueDKIMWeakKey] {
				seen[IssueDKIMWeakKey] = true
				out = append(out, ef(IssueDKIMWeakKey, sel.Selector, "high", "Weak DKIM key",
					"DKIM record uses a weak RSA key"))
			}
			if strings.Contains(value, "t=y") && !seen[IssueDKIMTestMode] {
				seen[IssueDKIMTestMode] = true
				out = append(
					out,
					ef(IssueDKIMTestMode, sel.Selector, "medium", "DKIM test mode enabled",
						"DKIM record has testing mode enabled"),
				)
			}
			if !strings.Contains(value, "k=") && !seen[IssueDKIMMissingTags] {
				seen[IssueDKIMMissingTags] = true
				out = append(
					out,
					ef(IssueDKIMMissingTags, sel.Selector, "info", "DKIM missing tags",
						"DKIM record omits the recommended 'k=' key-type tag"),
				)
			}
		}
	}
	if !dkimHasValidRecord(ev) && ev.HandlesEmail && dkimAllDeterminate(ev) {
		out = append(out, ef(
			IssueDKIMMissing,
			"",
			"high",
			"Missing DKIM",
			fmt.Sprintf(
				"No DKIM records found for any common selectors and domain has MX records. Checked: %s",
				strings.Join(ev.DKIMSelectorsChecked, ", "),
			),
		))
	}
	return out
}

func extractKeyFromDKIM(dkimRecord string) string {
	if !strings.Contains(dkimRecord, "p=") {
		return ""
	}
	parts := strings.Split(dkimRecord, "p=")
	if len(parts) < 2 {
		return ""
	}
	keyPart := parts[1]
	if end := strings.IndexAny(keyPart, ";"); end != -1 {
		return keyPart[:end]
	}
	return keyPart
}

func dmarcFindings(ev EmailSecurityEvidence) []checks.Finding {
	switch ev.DMARCStatus {
	case ResolutionData:
		var out []checks.Finding
		for _, value := range ev.DMARCRecords {
			if dmarcPrefix.MatchString(value) {
				out = append(out, dmarcRecordFindings(value)...)
			}
		}
		return out
	case ResolutionEmpty:
		if ev.HandlesEmail {
			return []checks.Finding{ef(IssueDMARCMissing, "", "critical", "Missing DMARC",
				"No DMARC record found for domain that handles email.")}
		}
		return nil
	default: // indeterminate -> unknown -> emit nothing
		return nil
	}
}

func dmarcRecordFindings(record string) []checks.Finding {
	var out []checks.Finding
	tags := parseDMARCTags(record)
	policy := tags["p"]
	subPolicy := tags["sp"]
	missingTags := tags["rua"] == "" || tags["ruf"] == ""
	pct := dmarcPct(tags)
	enforcing := policy == "quarantine" || policy == "reject"

	switch policy {
	case "reject":
	case "quarantine":
		out = append(out, ef(IssueDMARCQuarantine, "", "medium", "DMARC quarantine policy",
			"DMARC policy is 'quarantine'; 'reject' is recommended for full enforcement"))
	default:
		out = append(out, ef(IssueDMARCWeakPolicy, "", "high", "Weak DMARC policy",
			"DMARC policy is 'none' (monitoring only) and does not enforce"))
	}

	spWeaker := subPolicy != "" && dmarcPolicyRank(subPolicy) < dmarcPolicyRank(policy)
	if enforcing {
		if pct < 100 {
			out = append(out, ef(
				IssueDMARCReducedPct,
				"",
				"medium",
				"DMARC partial coverage",
				fmt.Sprintf(
					"DMARC pct=%d applies the policy to only part of the mail stream",
					pct,
				),
			))
		}
		if spWeaker {
			out = append(out, ef(
				IssueDMARCWeakSubPol,
				"",
				"medium",
				"DMARC weak subdomain policy",
				fmt.Sprintf(
					"DMARC subdomain policy 'sp=%s' is weaker than the domain policy 'p=%s'",
					subPolicy,
					policy,
				),
			))
		}
	}
	if missingTags {
		out = append(out, ef(IssueDMARCMissingTags, "", "info", "DMARC missing reporting tags",
			"DMARC record is missing recommended reporting tags (rua, ruf)"))
	}
	return out
}

func parseDMARCTags(record string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	return tags
}

func dmarcPct(tags map[string]string) int {
	v, ok := tags["pct"]
	if !ok || v == "" {
		return 100
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 100
	}
	return n
}

func dmarcPolicyRank(p string) int {
	switch p {
	case "reject":
		return 2
	case "quarantine":
		return 1
	default:
		return 0
	}
}

func bimiFindings(ev EmailSecurityEvidence) []checks.Finding {
	if !ev.HandlesEmail || ev.BIMIRecord == "" {
		return nil
	}
	var out []checks.Finding
	tags := parseKVTags(ev.BIMIRecord)
	if ev.DMARCStatus != ResolutionIndeterminate && !dmarcEnforced(ev.DMARCRecords) {
		out = append(out, ef(IssueBIMIRequiresDMARC, "", "medium", "BIMI requires enforced DMARC",
			"BIMI is published but DMARC is not enforced; BIMI requires p=quarantine or p=reject"))
	}
	if logo := tags["l"]; logo == "" || !isHTTPSURL(logo) || !isSVGURL(logo) {
		out = append(out, ef(IssueBIMIInvalidLogo, "", "low", "BIMI invalid logo",
			"BIMI l= must reference an HTTPS URL to an SVG logo"))
	}
	if vmc := tags["a"]; vmc != "" && !isHTTPSURL(vmc) {
		out = append(out, ef(IssueBIMIInvalidVMC, "", "low", "BIMI invalid VMC",
			"BIMI a= (VMC certificate) must reference an HTTPS URL"))
	}
	return out
}

func dmarcEnforced(dmarcRecords []string) bool {
	for _, r := range dmarcRecords {
		if dmarcPrefix.MatchString(r) {
			p := parseDMARCTags(r)["p"]
			return p == "quarantine" || p == "reject"
		}
	}
	return false
}

func parseKVTags(record string) map[string]string { return parseDMARCTags(record) }

func isHTTPSURL(u string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(u)), "https://")
}

func isSVGURL(u string) bool {
	path := strings.TrimSpace(u)
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	return strings.HasSuffix(strings.ToLower(path), ".svg")
}

func (d EmailSecurityDetector) mtaStsFindings(ev EmailSecurityEvidence) []checks.Finding {
	if !ev.HandlesEmail || !ev.MTASTSConfigured {
		return nil
	}
	policy, ok := parseMTASTSPolicy(ev.MTASTSPolicyBody)
	if !ev.MTASTSPolicyReached || ev.MTASTSPolicyStatus != 200 || !ok {
		return []checks.Finding{
			ef(
				IssueMTASTSPolicyUnreachable,
				"",
				"low",
				"MTA-STS policy unreachable",
				"MTA-STS TXT record is published but its HTTPS policy file could not be fetched or parsed",
			),
		}
	}
	var out []checks.Finding
	if policy.mode != "enforce" {
		out = append(out, ef(
			IssueMTASTSModeNotEnforcing,
			"",
			"low",
			"MTA-STS not enforcing",
			fmt.Sprintf(
				"MTA-STS policy mode is %q; only mode=enforce protects mail in transit",
				policy.mode,
			),
		))
	}
	if !mxSetCovered(policy.mx, ev.MXTargets) {
		out = append(out, ef(IssueMTASTSMXMismatch, "", "medium", "MTA-STS MX mismatch",
			"MTA-STS policy mx list does not cover the domain's published MX hosts"))
	}
	if policy.maxAge < d.MTASTSMinMaxAge {
		out = append(out, ef(
			IssueMTASTSShortMaxAge,
			"",
			"info",
			"MTA-STS short max_age",
			fmt.Sprintf(
				"MTA-STS max_age is %ds; a short window weakens downgrade protection (recommend >= %ds)",
				policy.maxAge,
				d.MTASTSMinMaxAge,
			),
		))
	}
	return out
}

type mtaStsPolicy struct {
	mode   string
	mx     []string
	maxAge int
}

func parseMTASTSPolicy(body string) (mtaStsPolicy, bool) {
	var p mtaStsPolicy
	var version string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "version":
			version = value
		case "mode":
			p.mode = strings.ToLower(value)
		case "mx":
			if value != "" {
				p.mx = append(p.mx, value)
			}
		case "max_age":
			p.maxAge, _ = strconv.Atoi(value)
		}
	}
	if version == "" || p.mode == "" || len(p.mx) == 0 {
		return p, false
	}
	return p, true
}

func mxSetCovered(patterns, mxTargets []string) bool {
	for _, t := range mxTargets {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(t)), ".")
		if host == "" {
			continue
		}
		matched := false
		for _, pat := range patterns {
			if mtaStsMxMatch(pat, host) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func mtaStsMxMatch(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return pattern == host
}

func tlsRptFindings(ev EmailSecurityEvidence) []checks.Finding {
	if !ev.HandlesEmail || ev.TLSRPTRecord == "" {
		return nil
	}
	if !tlsRptHasValidRua(ev.TLSRPTRecord) {
		return []checks.Finding{ef(IssueTLSRPTInvalidRua, "", "low", "TLS-RPT invalid rua",
			"TLS-RPT record has no valid rua reporting endpoint (expected mailto: or https:)")}
	}
	return nil
}

func tlsRptHasValidRua(record string) bool {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		key, value, found := strings.Cut(part, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "rua") {
			continue
		}
		for _, endpoint := range strings.Split(value, ",") {
			endpoint = strings.ToLower(strings.TrimSpace(endpoint))
			if strings.HasPrefix(endpoint, "mailto:") || strings.HasPrefix(endpoint, "https:") {
				return true
			}
		}
	}
	return false
}
