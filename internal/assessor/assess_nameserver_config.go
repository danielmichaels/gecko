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
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

const (
	NSInsufficientNameservers = "insufficient_nameservers"
	NSSameProvider            = "same_provider"
	NSNoIPv6                  = "no_ipv6"
	NSNotResolvable           = "ns_not_resolvable"
	NSIsCNAME                 = "ns_is_cname"
)

// nsRecommendedCount is RFC 2182's minimum: a zone SHOULD have at least two
// nameservers, ideally on diverse networks.
const nsRecommendedCount = 2

// AssessNameserverConfig evaluates a domain's delegated nameserver set for
// redundancy and per-nameserver hygiene. It reads the already-collected
// authoritative NS set from ns_records, then actively resolves each nameserver
// (CNAME/A/AAAA) through the rate-limited resolver to detect missing glue,
// illegal CNAME aliasing, and IPv6 coverage gaps.
//
// Two checks from the original scope are deliberately deferred to follow-ups:
// parent/child lame-delegation detection (gecko stores only the child's
// authoritative NS set today, not the parent's delegation), and true ASN/network
// diversity. This v1 approximates provider diversity by the registrable apex of
// each nameserver hostname, which catches the common all-NS-at-one-provider case.
func (a *Assessor) AssessNameserverConfig(ctx context.Context, domainUID string) error {
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

	records, err := a.store.RecordsGetNSByDomainID(
		ctx,
		pgtype.Int4{Int32: domain.ID, Valid: true},
	)
	if err != nil {
		a.logger.ErrorContext(
			ctx,
			"Failed to retrieve NS records",
			"domain",
			domain.Uid,
			"error",
			err,
		)
		return err
	}

	resolutions := a.resolveNameservers(records)
	if err := a.assessPerNameserver(ctx, domain.ID, resolutions); err != nil {
		return err
	}
	return a.assessRedundancy(ctx, domain.ID, resolutions)
}

// nsResolution captures the live resolution state of a single nameserver host.
type nsResolution struct {
	record     store.NsRecords
	hasAddress bool
	hasIPv6    bool
	isCNAME    bool
}

func (a *Assessor) resolveNameservers(records []store.NsRecords) []nsResolution {
	out := make([]nsResolution, 0, len(records))
	for _, r := range records {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Nameserver)), ".")
		res := nsResolution{record: r}
		if cname, ok := a.dnsClient.LookupCNAME(host); ok && len(cname) > 0 {
			res.isCNAME = true
		}
		if v4, ok := a.dnsClient.LookupA(host); ok && len(v4) > 0 {
			res.hasAddress = true
		}
		if v6, ok := a.dnsClient.LookupAAAA(host); ok && len(v6) > 0 {
			res.hasAddress = true
			res.hasIPv6 = true
		}
		out = append(out, res)
	}
	return out
}

func (a *Assessor) assessPerNameserver(
	ctx context.Context,
	domainID int32,
	resolutions []nsResolution,
) error {
	for _, res := range resolutions {
		cnameStatus := store.FindingStatusResolved
		cnameDetails := "Nameserver resolves to an address record, not a CNAME"
		if res.isCNAME {
			cnameStatus = store.FindingStatusOpen
			cnameDetails = "Nameserver target is a CNAME, which is illegal for NS records (RFC 2181 §10.3)"
		}
		if err := a.createNSConfigFinding(ctx, domainID, res.record, store.FindingSeverityMedium,
			cnameStatus, NSIsCNAME, cnameDetails); err != nil {
			return err
		}

		// A CNAME points somewhere, so it is "illegal" rather than "unresolvable";
		// only flag not-resolvable when there is neither an address nor a CNAME.
		resolveStatus := store.FindingStatusResolved
		resolveDetails := "Nameserver resolves to an A or AAAA address"
		if !res.hasAddress && !res.isCNAME {
			resolveStatus = store.FindingStatusOpen
			resolveDetails = "Nameserver does not resolve to any A or AAAA address (missing glue or lame delegation)"
		}
		if err := a.createNSConfigFinding(ctx, domainID, res.record, store.FindingSeverityMedium,
			resolveStatus, NSNotResolvable, resolveDetails); err != nil {
			return err
		}
	}
	return nil
}

func (a *Assessor) assessRedundancy(
	ctx context.Context,
	domainID int32,
	resolutions []nsResolution,
) error {
	count := int32(len(resolutions))

	insufficientStatus := store.FindingStatusResolved
	insufficientDetails := fmt.Sprintf(
		"Domain delegates to %d nameservers (RFC 2182 recommends at least %d)",
		count, nsRecommendedCount,
	)
	if int(count) < nsRecommendedCount {
		insufficientStatus = store.FindingStatusOpen
		insufficientDetails = fmt.Sprintf(
			"Domain delegates to only %d nameserver(s); RFC 2182 recommends at least %d",
			count, nsRecommendedCount,
		)
	}
	if err := a.createNSRedundancyFinding(ctx, domainID, store.FindingSeverityHigh,
		insufficientStatus, NSInsufficientNameservers, count, insufficientDetails); err != nil {
		return err
	}

	providerStatus := store.FindingStatusResolved
	providerDetails := "Nameservers are spread across multiple providers"
	if int(count) >= nsRecommendedCount && distinctProviders(resolutions) <= 1 {
		providerStatus = store.FindingStatusOpen
		providerDetails = "All nameservers belong to a single provider; an outage there takes the entire zone offline"
	}
	if err := a.createNSRedundancyFinding(ctx, domainID, store.FindingSeverityMedium,
		providerStatus, NSSameProvider, count, providerDetails); err != nil {
		return err
	}

	ipv6Status := store.FindingStatusResolved
	ipv6Details := "At least one nameserver is reachable over IPv6"
	if count > 0 && !anyIPv6(resolutions) {
		ipv6Status = store.FindingStatusOpen
		ipv6Details = "No nameserver in the set is reachable over IPv6; IPv6-only resolvers cannot reach the zone"
	}
	return a.createNSRedundancyFinding(ctx, domainID, store.FindingSeverityLow,
		ipv6Status, NSNoIPv6, count, ipv6Details)
}

// distinctProviders counts the unique registrable apexes across the nameserver
// set, the v1 proxy for provider diversity.
func distinctProviders(resolutions []nsResolution) int {
	providers := make(map[string]struct{}, len(resolutions))
	for _, res := range resolutions {
		providers[nsProviderApex(res.record.Nameserver)] = struct{}{}
	}
	return len(providers)
}

func anyIPv6(resolutions []nsResolution) bool {
	for _, res := range resolutions {
		if res.hasIPv6 {
			return true
		}
	}
	return false
}

// nsProviderApex returns the registrable domain (eTLD+1) of a nameserver host,
// falling back to the bare host when the public-suffix lookup fails.
func nsProviderApex(host string) string {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	apex, err := publicsuffix.Domain(h)
	if err != nil || apex == "" {
		return h
	}
	return apex
}

func (a *Assessor) createNSConfigFinding(
	ctx context.Context,
	domainID int32,
	record store.NsRecords,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType, details string,
) error {
	if _, err := a.store.AssessCreateNSConfigurationFinding(ctx, store.AssessCreateNSConfigurationFindingParams{
		DomainID:   pgtype.Int4{Int32: domainID, Valid: true},
		NsRecordID: pgtype.Int4{Int32: record.ID, Valid: true},
		Severity:   severity,
		Status:     status,
		IssueType:  issueType,
		Nameserver: record.Nameserver,
		Details:    pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(ctx, "failed to create ns configuration finding",
			"issue_type", issueType, "nameserver", record.Nameserver, "error", err)
		return fmt.Errorf(
			"create ns configuration finding %s/%s: %w",
			record.Nameserver,
			issueType,
			err,
		)
	}

	payload := observer.PayloadJSON(map[string]any{
		"issue_type": issueType,
		"nameserver": record.Nameserver,
		"severity":   string(severity),
		"status":     string(status),
		"details":    details,
	})
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, observer.EntityNSConfigurationFinding, issueType+"|"+record.Nameserver, payload,
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit ns configuration finding observation",
			"issue_type", issueType, "nameserver", record.Nameserver, "error", oErr)
	}
	return nil
}

func (a *Assessor) createNSRedundancyFinding(
	ctx context.Context,
	domainID int32,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType string,
	count int32,
	details string,
) error {
	if _, err := a.store.AssessCreateNameserverRedundancyFinding(ctx, store.AssessCreateNameserverRedundancyFindingParams{
		DomainID:         pgtype.Int4{Int32: domainID, Valid: true},
		Severity:         severity,
		Status:           status,
		IssueType:        issueType,
		NameserverCount:  count,
		RecommendedCount: nsRecommendedCount,
		Details:          pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(ctx, "failed to create nameserver redundancy finding",
			"issue_type", issueType, "error", err)
		return fmt.Errorf("create nameserver redundancy finding %s: %w", issueType, err)
	}

	payload := observer.PayloadJSON(map[string]any{
		"issue_type":        issueType,
		"severity":          string(severity),
		"status":            string(status),
		"nameserver_count":  count,
		"recommended_count": nsRecommendedCount,
		"details":           details,
	})
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, observer.EntityNameserverRedundancyFinding, issueType, payload,
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit nameserver redundancy finding observation",
			"issue_type", issueType, "error", oErr)
	}
	return nil
}
