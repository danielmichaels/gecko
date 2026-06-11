package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/scanner"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	DNSSECNotEnabled    = "dnssec_not_enabled"
	DNSSECBrokenChain   = "dnssec_broken_chain"
	DNSSECWeakAlgorithm = "dnssec_weak_algorithm"
	DNSSECEnabled       = "dnssec_enabled"
)

// deprecatedDNSSECAlgorithms maps DNSSEC algorithm numbers (RFC 8624) that are
// deprecated/insecure for signing to their names.
var deprecatedDNSSECAlgorithms = map[string]string{
	"1": "RSAMD5",
	"3": "DSA",
	"5": "RSASHA1",
	"6": "DSA-NSEC3-SHA1",
	"7": "RSASHA1-NSEC3-SHA1",
}

// AssessDNSSEC interprets the stored DNSSEC scan state and records findings that
// distinguish absent DNSSEC (informational) from a broken chain of trust (an
// availability risk) and from a deprecated signing algorithm.
func (a *Assessor) AssessDNSSEC(ctx context.Context, domainUID string) error {
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

	result, err := a.store.ScannersGetDNSSECResult(ctx, pgtype.Int4{Int32: domain.ID, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			a.logger.InfoContext(ctx, "No DNSSEC scan result to assess", "domain", domain.Uid)
			return nil
		}
		a.logger.ErrorContext(ctx, "Failed to retrieve DNSSEC scan result", "error", err)
		return err
	}

	// DNSSEC lives at the zone apex; a non-apex name has nothing to assess.
	if result.Status == scanner.DNSSECNotApplicable {
		return nil
	}

	switch {
	case result.ValidationError.Valid && result.ValidationError.String != "":
		return a.createDNSSECFinding(ctx, domain.ID,
			store.FindingSeverityHigh, store.FindingStatusOpen, DNSSECBrokenChain,
			fmt.Sprintf("DNSSEC validation failed: %s", result.ValidationError.String))

	case !result.HasDnskey && !result.HasDs && !result.HasRrsig:
		return a.createDNSSECFinding(ctx, domain.ID,
			store.FindingSeverityInfo, store.FindingStatusCompliant, DNSSECNotEnabled,
			"DNSSEC is not enabled for this domain")

	case result.HasDnskey && result.HasDs && result.HasRrsig:
		if err := a.createDNSSECFinding(ctx, domain.ID,
			store.FindingSeverityInfo, store.FindingStatusCompliant, DNSSECEnabled,
			"DNSSEC is enabled with a complete chain of trust"); err != nil {
			return err
		}
		if names := deprecatedAlgorithmNames(result.Algorithms); len(names) > 0 {
			return a.createDNSSECFinding(
				ctx,
				domain.ID,
				store.FindingSeverityMedium,
				store.FindingStatusOpen,
				DNSSECWeakAlgorithm,
				fmt.Sprintf(
					"DNSSEC uses deprecated signing algorithm(s): %s",
					strings.Join(names, ", "),
				),
			)
		}
		return nil

	default:
		return a.createDNSSECFinding(ctx, domain.ID,
			store.FindingSeverityHigh, store.FindingStatusOpen, DNSSECBrokenChain,
			"DNSSEC is partially deployed: missing DNSKEY, DS, or RRSIG records")
	}
}

func deprecatedAlgorithmNames(algorithms []string) []string {
	var names []string
	for _, alg := range algorithms {
		if name, ok := deprecatedDNSSECAlgorithms[strings.TrimSpace(alg)]; ok {
			names = append(names, name)
		}
	}
	return names
}

func (a *Assessor) createDNSSECFinding(
	ctx context.Context,
	domainID int32,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType, details string,
) error {
	if _, err := a.store.AssessCreateDNSSECFinding(ctx, store.AssessCreateDNSSECFindingParams{
		DomainID:  pgtype.Int4{Int32: domainID, Valid: true},
		Severity:  severity,
		Status:    status,
		IssueType: issueType,
		Details:   pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(
			ctx,
			"failed to create dnssec finding",
			"issue_type",
			issueType,
			"error",
			err,
		)
		return fmt.Errorf("create dnssec finding %s: %w", issueType, err)
	}

	payload := observer.PayloadJSON(map[string]any{
		"issue_type": issueType,
		"severity":   string(severity),
		"status":     string(status),
		"details":    details,
	})
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, observer.EntityDNSSECFinding, issueType, payload,
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit dnssec finding observation",
			"issue_type", issueType, "error", oErr)
	}
	return nil
}
