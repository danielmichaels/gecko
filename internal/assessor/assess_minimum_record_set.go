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
	MinRecordInsufficientNS       = "insufficient_nameservers"
	MinRecordMissingApexAddress   = "missing_apex_address"
	MinRecordMissingIPv6          = "missing_ipv6"
	MinRecordMissingSOA           = "missing_soa"
	MinRecordMissingMX            = "missing_mx"
	MinRecordSOATimers            = "soa_timers_out_of_range"
	MinRecordSOASerial            = "soa_serial_format"
	MinRecordSOAMNameUnresolvable = "soa_mname_unresolvable"
	MinRecordSOARName             = "soa_rname_malformed"
)

const recommendedNameserverCount = 2

// soaTimerRange holds an inclusive RFC 1912 recommended range for a SOA timer.
type soaTimerRange struct {
	name   string
	value  int32
	lo, hi int32
}

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

	if domain.DomainType != store.DomainTypeTld {
		return nil
	}

	id := pgtype.Int4{Int32: domain.ID, Valid: true}
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

	if err := a.assessNameservers(ctx, domain.ID, ns); err != nil {
		return err
	}
	if err := a.assessApexAddress(ctx, domain.ID, len(aRecs) > 0, len(aaaa) > 0); err != nil {
		return err
	}
	if err := a.assessSOA(ctx, domain.ID, soa); err != nil {
		return err
	}
	return a.assessMailRouting(ctx, domain.ID, mx, txt)
}

func (a *Assessor) assessNameservers(
	ctx context.Context,
	domainID int32,
	ns []store.NsRecords,
) error {
	status := store.FindingStatusResolved
	details := fmt.Sprintf("%d nameservers published", len(ns))
	if len(ns) < recommendedNameserverCount {
		status = store.FindingStatusOpen
		details = fmt.Sprintf(
			"Only %d nameserver(s) published; RFC 2182 recommends at least %d on separate networks",
			len(ns), recommendedNameserverCount,
		)
	}
	return a.createMinRecordFinding(ctx, domainID,
		store.FindingSeverityHigh, status, MinRecordInsufficientNS, "NS", details)
}

func (a *Assessor) assessApexAddress(
	ctx context.Context,
	domainID int32,
	hasA, hasAAAA bool,
) error {
	apexStatus := store.FindingStatusResolved
	apexDetails := "Apex resolves to an address record"
	if !hasA && !hasAAAA {
		apexStatus = store.FindingStatusOpen
		apexDetails = "Apex publishes no A or AAAA record, so it does not resolve to an address"
	}
	if err := a.createMinRecordFinding(ctx, domainID,
		store.FindingSeverityMedium, apexStatus, MinRecordMissingApexAddress, "A", apexDetails); err != nil {
		return err
	}

	// IPv6 is advisory and only meaningful once the apex resolves over IPv4.
	if !hasA {
		return nil
	}
	ipv6Status := store.FindingStatusResolved
	ipv6Details := "Apex publishes an AAAA record"
	if !hasAAAA {
		ipv6Status = store.FindingStatusOpen
		ipv6Details = "Apex resolves over IPv4 but publishes no AAAA record"
	}
	return a.createMinRecordFinding(ctx, domainID,
		store.FindingSeverityInfo, ipv6Status, MinRecordMissingIPv6, "AAAA", ipv6Details)
}

func (a *Assessor) assessSOA(ctx context.Context, domainID int32, soa []store.SoaRecords) error {
	if len(soa) == 0 {
		return a.createMinRecordFinding(ctx, domainID,
			store.FindingSeverityMedium, store.FindingStatusOpen, MinRecordMissingSOA, "SOA",
			"No SOA record published at the zone apex")
	}
	if err := a.createMinRecordFinding(ctx, domainID,
		store.FindingSeverityMedium, store.FindingStatusResolved, MinRecordMissingSOA, "SOA",
		"SOA record present"); err != nil {
		return err
	}

	rec := soa[0]
	if err := a.assessSOATimers(ctx, domainID, rec); err != nil {
		return err
	}
	if err := a.assessSOASerial(ctx, domainID, rec); err != nil {
		return err
	}
	if err := a.assessSOAMName(ctx, domainID, rec); err != nil {
		return err
	}
	return a.assessSOARName(ctx, domainID, rec)
}

func (a *Assessor) assessSOATimers(
	ctx context.Context,
	domainID int32,
	rec store.SoaRecords,
) error {
	ranges := []soaTimerRange{
		{"refresh", rec.Refresh, 1200, 86400},
		{"retry", rec.Retry, 120, 7200},
		{"expire", rec.Expire, 604800, 2419200},
		{"minimum", rec.MinimumTtl, 300, 86400},
	}
	var offenders []string
	for _, r := range ranges {
		if r.value < r.lo || r.value > r.hi {
			offenders = append(
				offenders,
				fmt.Sprintf("%s=%d (recommended %d-%d)", r.name, r.value, r.lo, r.hi),
			)
		}
	}
	status := store.FindingStatusResolved
	details := "SOA timers fall within RFC 1912 recommended ranges"
	if len(offenders) > 0 {
		status = store.FindingStatusOpen
		details = "SOA timers outside RFC 1912 recommended ranges: " + strings.Join(offenders, ", ")
	}
	return a.createMinRecordFinding(ctx, domainID,
		store.FindingSeverityLow, status, MinRecordSOATimers, "SOA", details)
}

func (a *Assessor) assessSOASerial(
	ctx context.Context,
	domainID int32,
	rec store.SoaRecords,
) error {
	status := store.FindingStatusResolved
	details := "SOA serial uses the recommended YYYYMMDDnn format"
	if !serialLooksDateBased(rec.Serial) {
		status = store.FindingStatusOpen
		details = fmt.Sprintf(
			"SOA serial %d is not in the advisory date-based YYYYMMDDnn format",
			rec.Serial,
		)
	}
	return a.createMinRecordFinding(ctx, domainID,
		store.FindingSeverityInfo, status, MinRecordSOASerial, "SOA", details)
}

func (a *Assessor) assessSOAMName(ctx context.Context, domainID int32, rec store.SoaRecords) error {
	mname := strings.TrimSuffix(strings.TrimSpace(rec.Nameserver), ".")
	status := store.FindingStatusResolved
	details := fmt.Sprintf("SOA MNAME %q resolves to an address", mname)
	if !a.hostResolves(mname) {
		status = store.FindingStatusOpen
		details = fmt.Sprintf("SOA MNAME %q does not resolve to an A or AAAA record", mname)
	}
	return a.createMinRecordFinding(ctx, domainID,
		store.FindingSeverityMedium, status, MinRecordSOAMNameUnresolvable, "SOA", details)
}

func (a *Assessor) assessSOARName(ctx context.Context, domainID int32, rec store.SoaRecords) error {
	status := store.FindingStatusResolved
	details := "SOA RNAME is a well-formed responsible-party address"
	if !rnameWellFormed(rec.Email) {
		status = store.FindingStatusOpen
		details = fmt.Sprintf(
			"SOA RNAME %q is not a well-formed responsible-party address",
			rec.Email,
		)
	}
	return a.createMinRecordFinding(ctx, domainID,
		store.FindingSeverityLow, status, MinRecordSOARName, "SOA", details)
}

func (a *Assessor) assessMailRouting(
	ctx context.Context,
	domainID int32,
	mx []store.MxRecords,
	txt []store.TxtRecords,
) error {
	var hasMX, hasNullMX bool
	for _, m := range mx {
		if strings.TrimSuffix(strings.TrimSpace(m.Target), ".") == "" {
			hasNullMX = true
		} else {
			hasMX = true
		}
	}

	switch {
	case hasMX || hasNullMX:
		details := "Domain publishes MX records"
		if hasNullMX && !hasMX {
			details = "Domain publishes an explicit null-MX (RFC 7505), declaring it sends/receives no mail"
		}
		return a.createMinRecordFinding(
			ctx,
			domainID,
			store.FindingSeverityLow,
			store.FindingStatusResolved,
			MinRecordMissingMX,
			"MX",
			details,
		)
	case hasEmailIntent(txt):
		return a.createMinRecordFinding(ctx, domainID,
			store.FindingSeverityLow, store.FindingStatusOpen, MinRecordMissingMX, "MX",
			"Domain publishes email-authentication records (SPF/DMARC) but no MX or null-MX")
	default:
		// No mail signal and no MX: nothing to assert.
		return nil
	}
}

// hostResolves reports whether a hostname has an A or AAAA record. This is the
// only outbound lookup in the assessor; it goes through the shared rate-limited,
// cached resolver.
func (a *Assessor) hostResolves(host string) bool {
	if host == "" {
		return false
	}
	if v, ok := a.dnsClient.LookupA(host); ok && len(v) > 0 {
		return true
	}
	if v, ok := a.dnsClient.LookupAAAA(host); ok && len(v) > 0 {
		return true
	}
	return false
}

// serialLooksDateBased reports whether a SOA serial plausibly follows the
// advisory YYYYMMDDnn convention (RFC 1912).
func serialLooksDateBased(serial int64) bool {
	if serial < 1900010100 || serial > 2999123199 {
		return false
	}
	date := serial / 100
	year := date / 10000
	month := (date / 100) % 100
	day := date % 100
	return year >= 1970 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 && day <= 31
}

// rnameWellFormed reports whether a SOA RNAME (DNS-form responsible party, e.g.
// "hostmaster.example.com.") converts to a plausible email: a non-empty local
// part and a dotted domain part.
func rnameWellFormed(rname string) bool {
	r := strings.TrimSuffix(strings.TrimSpace(rname), ".")
	if r == "" {
		return false
	}
	dot := strings.Index(r, ".")
	if dot <= 0 || dot == len(r)-1 {
		return false
	}
	local, domain := r[:dot], r[dot+1:]
	return local != "" && strings.Contains(domain, ".")
}

func hasEmailIntent(txt []store.TxtRecords) bool {
	for _, t := range txt {
		v := strings.ToLower(t.Value)
		if strings.Contains(v, "v=spf1") || strings.Contains(v, "v=dmarc1") {
			return true
		}
	}
	return false
}

func (a *Assessor) createMinRecordFinding(
	ctx context.Context,
	domainID int32,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType, missingRecordType, details string,
) error {
	if _, err := a.store.AssessCreateMinimumRecordSetFinding(ctx, store.AssessCreateMinimumRecordSetFindingParams{
		DomainID:          pgtype.Int4{Int32: domainID, Valid: true},
		Severity:          severity,
		Status:            status,
		IssueType:         issueType,
		MissingRecordType: missingRecordType,
		Details:           pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(ctx, "failed to create minimum record set finding",
			"issue_type", issueType, "error", err)
		return fmt.Errorf("create minimum record set finding %s: %w", issueType, err)
	}

	payload := observer.PayloadJSON(map[string]any{
		"issue_type":          issueType,
		"missing_record_type": missingRecordType,
		"severity":            string(severity),
		"status":              string(status),
		"details":             details,
	})
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, observer.EntityMinimumRecordSetFinding, issueType, payload,
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit minimum record set finding observation",
			"issue_type", issueType, "error", oErr)
	}
	return nil
}
