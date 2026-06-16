package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
)

const DanglingNS = "dangling_ns"

// AssessDanglingNS detects dangling NS delegation / nameserver takeover: an NS
// record whose registrable parent domain does not exist (NXDOMAIN), which lets an
// attacker register that domain and serve authoritative DNS for the delegated
// zone — a full subdomain/zone takeover.
//
// This DNS-only v1 relies on the apex-NXDOMAIN signal. RDAP-confirmed
// registrability (distinguishing a freely-registerable domain from one in
// redemption, and an ns_takeover escalation) is deferred to the RDAP client
// tracked in issue #72. Findings are written to ns_configuration_findings,
// reusing the NS_CONFIG surfacing.
func (a *Assessor) AssessDanglingNS(ctx context.Context, domainUID string) error {
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

	domainApex := nsProviderApex(domain.Name)
	apexStatus := make(map[string]dnsclient.ResolutionStatus)

	for _, r := range records {
		apex := nsProviderApex(r.Nameserver)
		// In-bailiwick nameservers live under the domain being assessed; that apex
		// demonstrably exists, so there is nothing to take over.
		if apex == "" || apex == domainApex {
			continue
		}

		status, seen := apexStatus[apex]
		if !seen {
			_, status = a.dnsClient.LookupWithStatus(apex, dns.TypeSOA)
			apexStatus[apex] = status
		}

		switch status {
		case dnsclient.ResolutionEmpty:
			if err := a.createNSConfigFinding(ctx, domain.ID, r, store.FindingSeverityHigh,
				store.FindingStatusOpen, DanglingNS,
				fmt.Sprintf("Nameserver parent domain %q does not exist (NXDOMAIN); it may be registerable and used to hijack this delegation", apex)); err != nil {
				return err
			}
		case dnsclient.ResolutionData:
			if err := a.createNSConfigFinding(ctx, domain.ID, r, store.FindingSeverityHigh,
				store.FindingStatusResolved, DanglingNS,
				fmt.Sprintf("Nameserver parent domain %q is registered", apex)); err != nil {
				return err
			}
		default:
			// ResolutionIndeterminate (SERVFAIL/timeout): do not flag on uncertainty.
		}
	}
	return nil
}
