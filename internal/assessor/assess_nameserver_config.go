package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
	"github.com/weppos/publicsuffix-go/publicsuffix"
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

	ev := a.collectNameserverConfig(domain.Name, records)
	found, err := detect.NameserverConfigDetector{RecommendedCount: nsRecommendedCount}.Detect(ev)
	if err != nil {
		return err
	}
	return a.reconcile(ctx, domain.Name, detect.CheckNameserverConfig, found)
}

// collectNameserverConfig resolves each delegated nameserver (CNAME/A/AAAA via the
// 3-way status API) and, for out-of-bailiwick nameservers, the registrable-parent
// SOA (memoized per apex) that drives the dangling-delegation check. This one
// collector feeds both the config and dangling-NS findings under nameserver_config.
func (a *Assessor) collectNameserverConfig(
	domainName string,
	records []store.NsRecords,
) detect.NameserverConfigEvidence {
	domainApex := nsProviderApex(domainName)
	apexStatus := make(map[string]dnsclient.ResolutionStatus)
	ev := detect.NameserverConfigEvidence{DomainName: domainName}

	for _, r := range records {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Nameserver)), ".")
		_, cnameSt := a.dnsClient.LookupWithStatus(host, dns.TypeCNAME)
		_, aSt := a.dnsClient.LookupWithStatus(host, dns.TypeA)
		_, aaaaSt := a.dnsClient.LookupWithStatus(host, dns.TypeAAAA)

		nse := detect.NameserverEvidence{
			Host:        r.Nameserver,
			CNAMEStatus: resolutionString(cnameSt),
			AStatus:     resolutionString(aSt),
			AAAAStatus:  resolutionString(aaaaSt),
		}
		apex := nsProviderApex(r.Nameserver)
		nse.InBailiwick = apex == "" || apex == domainApex
		if !nse.InBailiwick {
			st, seen := apexStatus[apex]
			if !seen {
				_, st = a.dnsClient.LookupWithStatus(apex, dns.TypeSOA)
				apexStatus[apex] = st
			}
			nse.ApexStatus = resolutionString(st)
		}
		ev.Nameservers = append(ev.Nameservers, nse)
	}
	return ev
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
