package assessor

import (
	"context"
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	BIMIAuthType     = "BIMI"
	bimiStandardName = "BIMI (AuthIndicators WG)"

	BIMICompliant             = "bimi_compliant"
	BIMINotConfigured         = "bimi_not_configured"
	BIMIRequiresEnforcedDMARC = "bimi_requires_enforced_dmarc"
	BIMIInvalidLogo           = "bimi_invalid_logo"
	BIMIInvalidVMC            = "bimi_invalid_vmc"
)

// assessBIMI evaluates the optional BIMI brand-indicator record at
// default._bimi.<domain>. BIMI is opt-in, so its absence is recorded as an
// informational not-applicable finding rather than a gap. When present it must
// reference an HTTPS SVG logo (l=), an HTTPS VMC certificate if a VMC is declared
// (a=), and crucially requires an enforced DMARC policy (p=quarantine|reject) or
// mailbox providers will not display the indicator.
func (a *Assessor) assessBIMI(ctx context.Context, d assessData) error {
	defer func() { a.logger.DebugContext(ctx, "assess BIMI complete", "domain_id", d.domainID) }()

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

	bimiRecord := a.lookupBIMIRecord(domain.Name)
	if bimiRecord == "" {
		return a.createComplianceFinding(ctx, d.domainID, BIMIAuthType,
			store.FindingSeverityInfo, store.FindingStatusNotApplicable, BIMINotConfigured,
			"BIMI is not configured (optional brand-indicator feature)")
	}

	tags := parseBIMITags(bimiRecord)
	issues := false

	if !a.dmarcEnforced(domain.Name) {
		issues = true
		if err := a.createComplianceFinding(ctx, d.domainID, BIMIAuthType,
			store.FindingSeverityMedium, store.FindingStatusOpen, BIMIRequiresEnforcedDMARC,
			"BIMI is published but DMARC is not enforced; BIMI requires p=quarantine or p=reject"); err != nil {
			return err
		}
	}

	logo := tags["l"]
	if logo == "" || !isHTTPSURL(logo) || !isSVGURL(logo) {
		issues = true
		if err := a.createComplianceFinding(ctx, d.domainID, BIMIAuthType,
			store.FindingSeverityLow, store.FindingStatusOpen, BIMIInvalidLogo,
			"BIMI l= must reference an HTTPS URL to an SVG logo"); err != nil {
			return err
		}
	}

	if vmc := tags["a"]; vmc != "" && !isHTTPSURL(vmc) {
		issues = true
		if err := a.createComplianceFinding(ctx, d.domainID, BIMIAuthType,
			store.FindingSeverityLow, store.FindingStatusOpen, BIMIInvalidVMC,
			"BIMI a= (VMC certificate) must reference an HTTPS URL"); err != nil {
			return err
		}
	}

	if !issues {
		return a.createComplianceFinding(ctx, d.domainID, BIMIAuthType,
			store.FindingSeverityInfo, store.FindingStatusClosed, BIMICompliant,
			"BIMI is configured with a valid logo and enforced DMARC")
	}
	return nil
}

func (a *Assessor) lookupBIMIRecord(domainName string) string {
	records, found := a.dnsClient.LookupTXT("default._bimi." + domainName)
	if !found {
		return ""
	}
	for _, r := range records {
		if strings.HasPrefix(strings.TrimSpace(r), "v=BIMI1") {
			return r
		}
	}
	return ""
}

// dmarcEnforced reports whether the domain publishes a DMARC record with an
// enforcing policy (quarantine or reject).
func (a *Assessor) dmarcEnforced(domainName string) bool {
	records, found := a.dnsClient.LookupTXT("_dmarc." + domainName)
	if !found {
		return false
	}
	for _, r := range records {
		if DMARCPrefix.MatchString(r) {
			p := parseDMARCTags(r)["p"]
			return p == "quarantine" || p == "reject"
		}
	}
	return false
}

func parseBIMITags(record string) map[string]string {
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

func (a *Assessor) createComplianceFinding(
	ctx context.Context,
	domainID int,
	authType string,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType, details string,
) error {
	if _, err := a.store.AssessCreateEmailAuthComplianceFinding(ctx, store.AssessCreateEmailAuthComplianceFindingParams{
		DomainID:     pgtype.Int4{Int32: int32(domainID), Valid: true},
		Severity:     severity,
		Status:       status,
		AuthType:     authType,
		IssueType:    issueType,
		StandardName: pgtype.Text{String: bimiStandardName, Valid: true},
		Details:      pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(ctx, "failed to create email auth compliance finding",
			"auth_type", authType, "issue_type", issueType, "error", err)
		return fmt.Errorf(
			"create email auth compliance finding %s/%s: %w",
			authType,
			issueType,
			err,
		)
	}

	payload := observer.PayloadJSON(map[string]any{
		"auth_type":  authType,
		"issue_type": issueType,
		"severity":   string(severity),
		"status":     string(status),
		"details":    details,
	})
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, observer.EntityEmailAuthComplianceFinding, authType+"|"+issueType, payload,
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit email auth compliance observation",
			"auth_type", authType, "issue_type", issueType, "error", oErr)
	}
	return nil
}
