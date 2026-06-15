package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	CAAMissing             = "caa_missing"
	CAAAllowsAnyCA         = "caa_allows_any_ca"
	CAAUntrustedIssuer     = "caa_untrusted_issuer"
	CAAUnknownCriticalFlag = "caa_unknown_critical_flag"
	CAAConflictingRecords  = "caa_conflicting_records"
	CAARequiredForCert     = "caa_required_for_cert"
	CAAMissingIodef        = "missing_iodef"
)

const (
	caaStandardName = "CAA RFC 8659"
	caaCriticalFlag = 128
)

// defaultTrustedCAs is the built-in allowlist of CAA issuer identifiers (the
// domain published in an `issue`/`issuewild` property) for well-known public
// CAs. An `issue` value outside this set is surfaced as a low-severity finding
// for human review; the list will drift over time and needs occasional upkeep.
var defaultTrustedCAs = map[string]struct{}{
	"letsencrypt.org": {},
	"digicert.com":    {},
	"sectigo.com":     {},
	"comodoca.com":    {},
	"globalsign.com":  {},
	"google.com":      {},
	"pki.goog":        {},
	"amazon.com":      {},
	"amazonaws.com":   {},
	"amazontrust.com": {},
	"awstrust.com":    {},
	"godaddy.com":     {},
	"ssl.com":         {},
	"entrust.net":     {},
	"buypass.com":     {},
	"actalis.it":      {},
	"certainly.com":   {},
	"microsoft.com":   {},
}

// AssessCAA interprets the already-collected CAA records for a domain and
// records configuration-quality findings (missing/unrestricted/untrusted
// issuance, unknown critical flags, conflicting policy) plus standards
// compliance findings (CAA required for cert-bearing domains, missing iodef).
// It reads structured records from caa_records; no DNS egress occurs here.
func (a *Assessor) AssessCAA(ctx context.Context, domainUID string) error {
	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		Uid:      domainUID,
		TenantID: pgtype.Int4{Int32: a.identity.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("domain %s not found in database", domainUID)
		}
		a.logger.ErrorContext(ctx, "Error looking up domain", "domain", domainUID, "error", err)
		return err
	}

	records, err := a.store.RecordsGetCAAByDomainID(ctx, pgtype.Int4{Int32: domain.ID, Valid: true})
	if err != nil {
		a.logger.ErrorContext(
			ctx,
			"Failed to retrieve CAA records",
			"domain",
			domain.Uid,
			"error",
			err,
		)
		return err
	}

	hasCert := a.domainHasCertificate(ctx, domain.ID)
	if len(records) == 0 {
		return a.assessMissingCAA(ctx, domain.ID, hasCert)
	}
	return a.assessPresentCAA(ctx, domain.ID, hasCert, records)
}

func (a *Assessor) domainHasCertificate(ctx context.Context, domainID int32) bool {
	_, err := a.store.ScannersGetCertificate(ctx, pgtype.Int4{Int32: domainID, Valid: true})
	if err == nil {
		return true
	}
	if !errors.Is(err, sql.ErrNoRows) {
		a.logger.WarnContext(ctx, "failed to check certificate presence for CAA assessment",
			"domain_id", domainID, "error", err)
	}
	return false
}

func (a *Assessor) assessMissingCAA(ctx context.Context, domainID int32, hasCert bool) error {
	severity := store.FindingSeverityInfo
	if hasCert {
		severity = store.FindingSeverityLow
	}
	if err := a.createCAAConfigFinding(ctx, domainID, severity, store.FindingStatusOpen,
		CAAMissing, "No CAA records are published at the domain apex"); err != nil {
		return err
	}
	if hasCert {
		return a.createCAAComplianceFinding(ctx, domainID,
			store.FindingSeverityLow, store.FindingStatusOpen, CAARequiredForCert,
			"Domain serves a certificate but publishes no CAA policy restricting issuance")
	}
	return nil
}

func (a *Assessor) assessPresentCAA(
	ctx context.Context,
	domainID int32,
	hasCert bool,
	records []store.CaaRecords,
) error {
	var (
		hasIssueTag        bool
		hasIodef           bool
		hasUnknownCritical bool
		hasNoIssuance      bool
		hasPermissiveIssue bool
		sawIssuer          bool
		untrusted          []string
	)
	for _, r := range records {
		switch strings.ToLower(strings.TrimSpace(r.Tag)) {
		case "issue", "issuewild":
			isIssue := strings.EqualFold(strings.TrimSpace(r.Tag), "issue")
			if isIssue {
				hasIssueTag = true
			}
			ca := caaIssuerDomain(r.Value)
			if ca == "" {
				if isIssue {
					hasNoIssuance = true
				}
				continue
			}
			sawIssuer = true
			if isIssue {
				hasPermissiveIssue = true
			}
			if !isTrustedCA(ca) {
				untrusted = append(untrusted, ca)
			}
		case "iodef":
			hasIodef = true
		default:
			if r.Flags&caaCriticalFlag != 0 {
				hasUnknownCritical = true
			}
		}
	}

	missingSeverity := store.FindingSeverityInfo
	if hasCert {
		missingSeverity = store.FindingSeverityLow
	}
	if err := a.createCAAConfigFinding(ctx, domainID, missingSeverity, store.FindingStatusResolved,
		CAAMissing, "CAA records are published at the domain apex"); err != nil {
		return err
	}

	anyCAStatus := store.FindingStatusResolved
	anyCADetails := "CAA records restrict certificate issuance to listed CAs"
	if !hasIssueTag {
		anyCAStatus = store.FindingStatusOpen
		anyCADetails = "CAA records exist but contain no issue property, so any CA may issue certificates"
	}
	if err := a.createCAAConfigFinding(ctx, domainID, store.FindingSeverityLow, anyCAStatus,
		CAAAllowsAnyCA, anyCADetails); err != nil {
		return err
	}

	if sawIssuer {
		issuerStatus := store.FindingStatusResolved
		issuerDetails := "All authorised CAs are well-known public issuers"
		if len(untrusted) > 0 {
			issuerStatus = store.FindingStatusOpen
			issuerDetails = fmt.Sprintf(
				"CAA authorises issuance by unrecognised CA(s): %s",
				strings.Join(untrusted, ", "),
			)
		}
		if err := a.createCAAConfigFinding(ctx, domainID, store.FindingSeverityLow, issuerStatus,
			CAAUntrustedIssuer, issuerDetails); err != nil {
			return err
		}
	}

	criticalStatus := store.FindingStatusResolved
	criticalDetails := "No unrecognised CAA properties carry the critical flag"
	if hasUnknownCritical {
		criticalStatus = store.FindingStatusOpen
		criticalDetails = "A CAA property gecko does not recognise has the critical flag set; conformant CAs must refuse issuance"
	}
	if err := a.createCAAConfigFinding(ctx, domainID, store.FindingSeverityMedium, criticalStatus,
		CAAUnknownCriticalFlag, criticalDetails); err != nil {
		return err
	}

	conflictStatus := store.FindingStatusResolved
	conflictDetails := "CAA issuance policy is internally consistent"
	if hasNoIssuance && hasPermissiveIssue {
		conflictStatus = store.FindingStatusOpen
		conflictDetails = "CAA contains a no-issuance directive (issue \";\") alongside a permissive issue property"
	}
	if err := a.createCAAConfigFinding(ctx, domainID, store.FindingSeverityMedium, conflictStatus,
		CAAConflictingRecords, conflictDetails); err != nil {
		return err
	}

	if hasCert {
		if err := a.createCAAComplianceFinding(ctx, domainID,
			store.FindingSeverityLow, store.FindingStatusResolved, CAARequiredForCert,
			"Cert-bearing domain publishes a CAA policy"); err != nil {
			return err
		}
	}

	iodefStatus := store.FindingStatusResolved
	iodefDetails := "CAA publishes an iodef reporting endpoint"
	if !hasIodef {
		iodefStatus = store.FindingStatusOpen
		iodefDetails = "CAA does not publish an iodef property for violation reporting"
	}
	return a.createCAAComplianceFinding(ctx, domainID, store.FindingSeverityInfo, iodefStatus,
		CAAMissingIodef, iodefDetails)
}

// caaIssuerDomain extracts the CA identifier from an issue/issuewild value,
// dropping any parameters after the first semicolon. An empty result denotes a
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

func (a *Assessor) createCAAConfigFinding(
	ctx context.Context,
	domainID int32,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType, details string,
) error {
	if _, err := a.store.AssessCreateCAAConfigurationFinding(ctx, store.AssessCreateCAAConfigurationFindingParams{
		DomainID:  pgtype.Int4{Int32: domainID, Valid: true},
		Severity:  severity,
		Status:    status,
		IssueType: issueType,
		Details:   pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(ctx, "failed to create caa configuration finding",
			"issue_type", issueType, "error", err)
		return fmt.Errorf("create caa configuration finding %s: %w", issueType, err)
	}

	payload := observer.PayloadJSON(map[string]any{
		"issue_type": issueType,
		"severity":   string(severity),
		"status":     string(status),
		"details":    details,
	})
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, observer.EntityCAAConfigurationFinding, issueType, payload,
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit caa configuration finding observation",
			"issue_type", issueType, "error", oErr)
	}
	return nil
}

func (a *Assessor) createCAAComplianceFinding(
	ctx context.Context,
	domainID int32,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType, details string,
) error {
	if _, err := a.store.AssessCreateCAAComplianceFinding(ctx, store.AssessCreateCAAComplianceFindingParams{
		DomainID:     pgtype.Int4{Int32: domainID, Valid: true},
		Severity:     severity,
		Status:       status,
		IssueType:    issueType,
		StandardName: pgtype.Text{String: caaStandardName, Valid: true},
		Details:      pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(ctx, "failed to create caa compliance finding",
			"issue_type", issueType, "error", err)
		return fmt.Errorf("create caa compliance finding %s: %w", issueType, err)
	}

	payload := observer.PayloadJSON(map[string]any{
		"issue_type":    issueType,
		"severity":      string(severity),
		"status":        string(status),
		"standard_name": caaStandardName,
		"details":       details,
	})
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, observer.EntityCAAComplianceFinding, issueType, payload,
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit caa compliance finding observation",
			"issue_type", issueType, "error", oErr)
	}
	return nil
}
