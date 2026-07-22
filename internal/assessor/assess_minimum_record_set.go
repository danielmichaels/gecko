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
)

const recommendedNameserverCount = 2

// AssessMinimumRecordSet checks that an apex domain publishes the records core
// services depend on (apex address, >=2 NS, SOA, MX when email is intended) and
// folds in SOA hygiene. It runs only for apex (tld) domains — NS/SOA are
// zone-apex concepts, so subdomains are skipped. Inputs come from already-stored
// records; only the SOA MNAME resolvability check performs a (rate-limited) lookup.
func (a *Assessor) AssessMinimumRecordSet(ctx context.Context, domainUID string) error {
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

	ev := detect.MinimumRecordSetEvidence{IsApex: domain.DomainType == store.DomainTypeTld}
	if ev.IsApex {
		if err := a.collectMinimumRecordSet(ctx, domain.ID, &ev); err != nil {
			return err
		}
	}

	found, err := detect.MinimumRecordSetDetector{MinNameservers: recommendedNameserverCount}.Detect(ev)
	if err != nil {
		return err
	}
	return a.reconcile(ctx, domain.Name, detect.CheckMinimumRecordSet, found)
}

// collectMinimumRecordSet fills the apex-hygiene evidence from stored records plus
// a live SOA MNAME resolvability lookup.
func (a *Assessor) collectMinimumRecordSet(
	ctx context.Context,
	domainID int32,
	ev *detect.MinimumRecordSetEvidence,
) error {
	id := pgtype.Int4{Int32: domainID, Valid: true}
	ns, err := a.store.RecordsGetNSByDomainID(ctx, id)
	if err != nil {
		return fmt.Errorf("get NS records: %w", err)
	}
	aRecs, err := a.store.RecordsGetAByDomainID(ctx, id)
	if err != nil {
		return fmt.Errorf("get A records: %w", err)
	}
	aaaa, err := a.store.RecordsGetAAAAByDomainID(ctx, id)
	if err != nil {
		return fmt.Errorf("get AAAA records: %w", err)
	}
	soa, err := a.store.RecordsGetSOAByDomainID(ctx, id)
	if err != nil {
		return fmt.Errorf("get SOA records: %w", err)
	}
	mx, err := a.store.RecordsGetMXByDomainID(ctx, id)
	if err != nil {
		return fmt.Errorf("get MX records: %w", err)
	}
	txt, err := a.store.RecordsGetTXTByDomainID(ctx, id)
	if err != nil {
		return fmt.Errorf("get TXT records: %w", err)
	}

	ev.NSLookedUp, ev.NSCount = true, len(ns)
	ev.ALookedUp, ev.HasA = true, len(aRecs) > 0
	ev.AAAALookedUp, ev.HasAAAA = true, len(aaaa) > 0
	ev.SOALookedUp = true
	if len(soa) > 0 {
		rec := soa[0]
		ev.SOAPresent = true
		ev.SOARefresh, ev.SOARetry, ev.SOAExpire, ev.SOAMinimumTTL = rec.Refresh, rec.Retry, rec.Expire, rec.MinimumTtl
		ev.SOASerial = rec.Serial
		ev.SOAMName = strings.TrimSuffix(strings.TrimSpace(rec.Nameserver), ".")
		ev.SOARName = rec.Email
		ev.SOAMNameLookedUp, ev.SOAMNameResolves = a.resolveHost(ev.SOAMName)
	}
	ev.MXLookedUp = true
	for _, m := range mx {
		if strings.TrimSuffix(strings.TrimSpace(m.Target), ".") == "" {
			ev.HasNullMX = true
		} else {
			ev.HasMX = true
		}
	}
	for _, t := range txt {
		ev.TXTValues = append(ev.TXTValues, t.Value)
	}
	return nil
}

// resolveHost reports whether a host has an A or AAAA record and whether the lookup
// was authoritative, so a SERVFAIL is not mistaken for "does not resolve".
func (a *Assessor) resolveHost(host string) (lookedUp, resolves bool) {
	if host == "" {
		return false, false
	}
	aVals, aStatus := a.dnsClient.LookupWithStatus(host, dns.TypeA)
	aaaaVals, aaaaStatus := a.dnsClient.LookupWithStatus(host, dns.TypeAAAA)
	lookedUp = aStatus != dnsclient.ResolutionIndeterminate || aaaaStatus != dnsclient.ResolutionIndeterminate
	resolves = len(aVals) > 0 || len(aaaaVals) > 0
	return lookedUp, resolves
}
