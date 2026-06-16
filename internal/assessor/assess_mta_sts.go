package assessor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	MTASTSAuthType     = "MTA-STS"
	mtaStsStandardName = "MTA-STS RFC 8461"

	MTASTSNotConfigured     = "mta_sts_not_configured"
	MTASTSPolicyUnreachable = "mta_sts_policy_unreachable"
	MTASTSModeNotEnforcing  = "mta_sts_mode_not_enforcing"
	MTASTSMXMismatch        = "mta_sts_mx_mismatch"
	MTASTSShortMaxAge       = "mta_sts_short_max_age"
	MTASTSCompliant         = "mta_sts_compliant"

	TLSRPTAuthType     = "TLS-RPT"
	tlsRptStandardName = "TLS-RPT RFC 8460"

	TLSRPTNotConfigured = "tls_rpt_not_configured"
	TLSRPTInvalidRua    = "tls_rpt_invalid_rua"
	TLSRPTCompliant     = "tls_rpt_compliant"
)

// mtaStsMinMaxAge is the policy max_age (seconds) below which MTA-STS offers weak
// protection: a short window lets a downgrade attacker wait out the cached policy.
// RFC 8461 recommends at least a few weeks; one week is the minimum we accept.
const mtaStsMinMaxAge = 604800

// assessMTASTS evaluates SMTP MTA Strict Transport Security: the _mta-sts TXT
// record plus the HTTPS policy file. MTA-STS is opt-in, so its absence is recorded
// as informational/not-applicable rather than a gap.
func (a *Assessor) assessMTASTS(ctx context.Context, d assessData) error {
	defer func() { a.logger.DebugContext(ctx, "assess MTA-STS complete", "domain_id", d.domainID) }()

	if !d.handlesEmail {
		return nil
	}

	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		TenantID: pgtype.Int4{Int32: a.identity.TenantID, Valid: true},
		ID:       int32(d.domainID),
	})
	if err != nil {
		return fmt.Errorf("get domain: %d %w", d.domainID, err)
	}

	if a.lookupTXTPrefixed("_mta-sts."+domain.Name, "v=STSv1") == "" {
		return a.createComplianceFinding(ctx, d.domainID, MTASTSAuthType, mtaStsStandardName,
			store.FindingSeverityInfo, store.FindingStatusNotApplicable, MTASTSNotConfigured,
			"MTA-STS is not configured (optional SMTP transport-security policy)")
	}

	policyURL := "https://mta-sts." + domain.Name + "/.well-known/mta-sts.txt"
	res := a.prober.Get(ctx, policyURL)
	policy, ok := parseMTASTSPolicy(res.Body)
	if !res.Reached || res.StatusCode != 200 || !ok {
		return a.createComplianceFinding(
			ctx,
			d.domainID,
			MTASTSAuthType,
			mtaStsStandardName,
			store.FindingSeverityLow,
			store.FindingStatusOpen,
			MTASTSPolicyUnreachable,
			"MTA-STS TXT record is published but its HTTPS policy file could not be fetched or parsed",
		)
	}

	issues := false
	if policy.mode != "enforce" {
		issues = true
		if err := a.createComplianceFinding(ctx, d.domainID, MTASTSAuthType, mtaStsStandardName,
			store.FindingSeverityLow, store.FindingStatusOpen, MTASTSModeNotEnforcing,
			fmt.Sprintf("MTA-STS policy mode is %q; only mode=enforce protects mail in transit", policy.mode)); err != nil {
			return err
		}
	}
	if !mxSetCovered(policy.mx, d.mxRecords) {
		issues = true
		if err := a.createComplianceFinding(ctx, d.domainID, MTASTSAuthType, mtaStsStandardName,
			store.FindingSeverityMedium, store.FindingStatusOpen, MTASTSMXMismatch,
			"MTA-STS policy mx list does not cover the domain's published MX hosts"); err != nil {
			return err
		}
	}
	if policy.maxAge < mtaStsMinMaxAge {
		issues = true
		if err := a.createComplianceFinding(ctx, d.domainID, MTASTSAuthType, mtaStsStandardName,
			store.FindingSeverityInfo, store.FindingStatusOpen, MTASTSShortMaxAge,
			fmt.Sprintf("MTA-STS max_age is %ds; a short window weakens downgrade protection (recommend >= %ds)", policy.maxAge, mtaStsMinMaxAge)); err != nil {
			return err
		}
	}

	if issues {
		return nil
	}
	return a.createComplianceFinding(ctx, d.domainID, MTASTSAuthType, mtaStsStandardName,
		store.FindingSeverityInfo, store.FindingStatusClosed, MTASTSCompliant,
		"MTA-STS is enforced with a valid policy covering the published MX hosts")
}

// assessTLSRPT evaluates SMTP TLS Reporting: the _smtp._tls TXT record and its
// rua reporting endpoint. Like MTA-STS it is opt-in.
func (a *Assessor) assessTLSRPT(ctx context.Context, d assessData) error {
	defer func() { a.logger.DebugContext(ctx, "assess TLS-RPT complete", "domain_id", d.domainID) }()

	if !d.handlesEmail {
		return nil
	}

	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		TenantID: pgtype.Int4{Int32: a.identity.TenantID, Valid: true},
		ID:       int32(d.domainID),
	})
	if err != nil {
		return fmt.Errorf("get domain: %d %w", d.domainID, err)
	}

	record := a.lookupTXTPrefixed("_smtp._tls."+domain.Name, "v=TLSRPTv1")
	if record == "" {
		return a.createComplianceFinding(ctx, d.domainID, TLSRPTAuthType, tlsRptStandardName,
			store.FindingSeverityInfo, store.FindingStatusNotApplicable, TLSRPTNotConfigured,
			"TLS-RPT is not configured (optional SMTP TLS reporting policy)")
	}

	if !tlsRptHasValidRua(record) {
		return a.createComplianceFinding(ctx, d.domainID, TLSRPTAuthType, tlsRptStandardName,
			store.FindingSeverityLow, store.FindingStatusOpen, TLSRPTInvalidRua,
			"TLS-RPT record has no valid rua reporting endpoint (expected mailto: or https:)")
	}

	return a.createComplianceFinding(ctx, d.domainID, TLSRPTAuthType, tlsRptStandardName,
		store.FindingSeverityInfo, store.FindingStatusClosed, TLSRPTCompliant,
		"TLS-RPT is configured with a valid reporting endpoint")
}

func (a *Assessor) lookupTXTPrefixed(name, prefix string) string {
	records, found := a.dnsClient.LookupTXT(name)
	if !found {
		return ""
	}
	for _, r := range records {
		if strings.HasPrefix(strings.TrimSpace(r), prefix) {
			return r
		}
	}
	return ""
}

// mtaStsPolicy is the parsed MTA-STS policy file (RFC 8461 §3.2).
type mtaStsPolicy struct {
	mode   string
	mx     []string
	maxAge int
}

// parseMTASTSPolicy parses the line-based "key: value" policy body. It reports ok
// only when the mandatory version/mode/mx fields are present.
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

// mxSetCovered reports whether every published MX host is matched by at least one
// MTA-STS policy mx pattern. An empty published MX set is trivially covered.
func mxSetCovered(patterns []string, mxRecords []store.MxRecords) bool {
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(mx.Target)), ".")
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

// mtaStsMxMatch matches one policy mx pattern against a host, supporting the
// single-label "*.example.com" wildcard form (RFC 8461 §4.1).
func mtaStsMxMatch(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return pattern == host
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
