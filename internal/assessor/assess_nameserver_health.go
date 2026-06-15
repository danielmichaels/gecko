package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
)

const (
	NSUnreachable      = "unreachable"
	NSNoTCPSupport     = "no_tcp_support"
	NSNoEDNSSupport    = "no_edns_support"
	NSHighLatency      = "high_latency"
	NSResolverMismatch = "resolver_mismatch"
)

// nsHealthRecordType is the record probed at every authoritative nameserver. The
// zone apex SOA is the canonical liveness + sync signal: its serial reveals
// whether secondaries have transferred the latest zone.
const nsHealthRecordType = "SOA"

// Latency tiers (Balanced preset) for an authoritative nameserver's response
// time, in milliseconds. Below the info threshold is recorded as resolved.
const (
	nsLatencyInfoMs   = 150
	nsLatencyLowMs    = 400
	nsLatencyMediumMs = 900
)

// NameserverProber probes a specific authoritative nameserver directly. The
// production implementation is *dnsclient.DNSClient; tests inject a fake.
type NameserverProber interface {
	ProbeNameserver(server, name string, qtype uint16) dnsclient.NSProbeResult
}

// nsAnswer is one reachable nameserver's apex-SOA answer, used to compare zone
// state across the authoritative set.
type nsAnswer struct {
	nameserver string
	serial     string
}

// AssessNameserverHealth probes each authoritative nameserver directly for the
// zone apex SOA and records reachability (UDP), TCP/EDNS0 support, response
// latency, and cross-nameserver answer consistency.
//
// The consistency check deliberately omits cross-scan dampening for now: DNS
// nameservers legitimately disagree during propagation, so divergence is flagged
// only at low severity with a "may be transient" note. Requiring divergence to
// persist across N scans needs cross-scan state that does not exist yet and is a
// tracked follow-up.
func (a *Assessor) AssessNameserverHealth(ctx context.Context, domainUID string) error {
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

	if a.nsProber == nil {
		a.logger.WarnContext(ctx, "nameserver health assessment skipped: no prober configured",
			"domain", domain.Uid)
		return nil
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

	var reachable []nsAnswer

	for _, r := range records {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Nameserver)), ".")
		probe := a.nsProber.ProbeNameserver(net.JoinHostPort(host, "53"), domain.Name, dns.TypeSOA)

		if err := a.recordReachability(ctx, domain.ID, r, probe); err != nil {
			return err
		}
		if !probe.Reachable {
			continue
		}
		if err := a.recordLatency(ctx, domain.ID, r.Nameserver, probe.RTT); err != nil {
			return err
		}
		if serial := strings.Join(probe.Answers, " "); serial != "" {
			reachable = append(reachable, nsAnswer{nameserver: r.Nameserver, serial: serial})
		}
	}

	return a.recordConsistency(ctx, domain.ID, reachable)
}

func (a *Assessor) recordReachability(
	ctx context.Context,
	domainID int32,
	record store.NsRecords,
	probe dnsclient.NSProbeResult,
) error {
	rtt := pgtype.Int4{}
	if probe.Reachable {
		rtt = pgtype.Int4{Int32: int32(probe.RTT.Milliseconds()), Valid: true}
	}

	reachStatus := store.FindingStatusResolved
	reachDetails := "Nameserver answered a direct UDP query"
	if !probe.Reachable {
		reachStatus = store.FindingStatusOpen
		reachDetails = "Nameserver did not answer a direct UDP query (unreachable or timing out)"
	}
	if err := a.createReachabilityFinding(ctx, domainID, record, store.FindingSeverityHigh,
		reachStatus, NSUnreachable, rtt, reachDetails); err != nil {
		return err
	}

	// TCP/EDNS are only meaningful when the server answers at all; for an
	// unreachable server they are recorded resolved so they do not double-count.
	tcpStatus := store.FindingStatusResolved
	tcpDetails := "Nameserver answers over TCP"
	if probe.Reachable && !probe.TCPOK {
		tcpStatus = store.FindingStatusOpen
		tcpDetails = "Nameserver does not answer over TCP, which is required for large responses and DNSSEC"
	}
	if err := a.createReachabilityFinding(ctx, domainID, record, store.FindingSeverityMedium,
		tcpStatus, NSNoTCPSupport, rtt, tcpDetails); err != nil {
		return err
	}

	ednsStatus := store.FindingStatusResolved
	ednsDetails := "Nameserver supports EDNS0"
	if probe.Reachable && !probe.HasEDNS {
		ednsStatus = store.FindingStatusOpen
		ednsDetails = "Nameserver does not support EDNS0, limiting modern DNS features and UDP payload size"
	}
	return a.createReachabilityFinding(ctx, domainID, record, store.FindingSeverityInfo,
		ednsStatus, NSNoEDNSSupport, rtt, ednsDetails)
}

func (a *Assessor) recordLatency(
	ctx context.Context,
	domainID int32,
	nameserver string,
	rtt time.Duration,
) error {
	ms := int32(rtt.Milliseconds())

	severity := store.FindingSeverityInfo
	status := store.FindingStatusOpen
	threshold := int32(nsLatencyInfoMs)
	switch {
	case ms >= nsLatencyMediumMs:
		severity, threshold = store.FindingSeverityMedium, nsLatencyMediumMs
	case ms >= nsLatencyLowMs:
		severity, threshold = store.FindingSeverityLow, nsLatencyLowMs
	case ms >= nsLatencyInfoMs:
		severity, threshold = store.FindingSeverityInfo, nsLatencyInfoMs
	default:
		status = store.FindingStatusResolved
	}

	details := fmt.Sprintf("Nameserver responded in %dms", ms)
	if status == store.FindingStatusOpen {
		details = fmt.Sprintf("Nameserver responded in %dms (exceeds %dms)", ms, threshold)
	}

	return a.createLatencyFinding(
		ctx,
		domainID,
		nameserver,
		severity,
		status,
		ms,
		threshold,
		details,
	)
}

func (a *Assessor) recordConsistency(
	ctx context.Context,
	domainID int32,
	answers []nsAnswer,
) error {
	if len(answers) == 0 {
		return nil
	}

	var divergentNS, divergentSerial string
	for _, ans := range answers[1:] {
		if ans.serial != answers[0].serial {
			divergentNS, divergentSerial = ans.nameserver, ans.serial
			break
		}
	}

	if divergentNS == "" {
		return a.createConsistencyFinding(ctx, domainID, store.FindingSeverityLow,
			store.FindingStatusResolved, answers[0].nameserver, answers[0].serial,
			answers[len(answers)-1].nameserver, answers[len(answers)-1].serial,
			"All authoritative nameservers agree on the apex SOA")
	}

	details := fmt.Sprintf(
		"Authoritative nameservers return divergent apex SOA records (may be transient propagation): %s",
		summarizeSerials(answers),
	)
	return a.createConsistencyFinding(ctx, domainID, store.FindingSeverityLow,
		store.FindingStatusOpen, answers[0].nameserver, answers[0].serial,
		divergentNS, divergentSerial, details)
}

func summarizeSerials(answers []nsAnswer) string {
	parts := make([]string, 0, len(answers))
	for _, a := range answers {
		parts = append(parts, fmt.Sprintf("%s=%q", a.nameserver, a.serial))
	}
	return strings.Join(parts, ", ")
}

func (a *Assessor) createReachabilityFinding(
	ctx context.Context,
	domainID int32,
	record store.NsRecords,
	severity store.FindingSeverity,
	status store.FindingStatus,
	issueType string,
	responseMs pgtype.Int4,
	details string,
) error {
	if _, err := a.store.AssessCreateNameserverReachabilityFinding(ctx, store.AssessCreateNameserverReachabilityFindingParams{
		DomainID:       pgtype.Int4{Int32: domainID, Valid: true},
		NsRecordID:     pgtype.Int4{Int32: record.ID, Valid: true},
		Severity:       severity,
		Status:         status,
		Nameserver:     record.Nameserver,
		IssueType:      issueType,
		ResponseTimeMs: responseMs,
		Details:        pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(ctx, "failed to create nameserver reachability finding",
			"issue_type", issueType, "nameserver", record.Nameserver, "error", err)
		return fmt.Errorf(
			"create nameserver reachability finding %s/%s: %w",
			record.Nameserver,
			issueType,
			err,
		)
	}
	a.emitFindingObservation(
		ctx,
		observer.EntityNameserverReachabilityFinding,
		issueType+"|"+record.Nameserver,
		map[string]any{
			"issue_type": issueType, "nameserver": record.Nameserver,
			"severity": string(severity), "status": string(status), "details": details,
		},
	)
	return nil
}

func (a *Assessor) createLatencyFinding(
	ctx context.Context,
	domainID int32,
	nameserver string,
	severity store.FindingSeverity,
	status store.FindingStatus,
	latencyMs, thresholdMs int32,
	details string,
) error {
	if _, err := a.store.AssessCreateDNSResolutionLatencyFinding(ctx, store.AssessCreateDNSResolutionLatencyFindingParams{
		DomainID:    pgtype.Int4{Int32: domainID, Valid: true},
		Severity:    severity,
		Status:      status,
		RecordType:  nsHealthRecordType,
		Resolver:    nameserver,
		LatencyMs:   latencyMs,
		ThresholdMs: thresholdMs,
		Details:     pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(ctx, "failed to create dns resolution latency finding",
			"nameserver", nameserver, "error", err)
		return fmt.Errorf("create dns resolution latency finding %s: %w", nameserver, err)
	}
	a.emitFindingObservation(
		ctx,
		observer.EntityDNSResolutionLatencyFinding,
		NSHighLatency+"|"+nameserver,
		map[string]any{
			"issue_type": NSHighLatency, "resolver": nameserver, "record_type": nsHealthRecordType,
			"latency_ms": latencyMs, "threshold_ms": thresholdMs,
			"severity": string(severity), "status": string(status), "details": details,
		},
	)
	return nil
}

func (a *Assessor) createConsistencyFinding(
	ctx context.Context,
	domainID int32,
	severity store.FindingSeverity,
	status store.FindingStatus,
	resolver1, result1, resolver2, result2, details string,
) error {
	if _, err := a.store.AssessCreateDNSResolutionConsistencyFinding(ctx, store.AssessCreateDNSResolutionConsistencyFindingParams{
		DomainID:        pgtype.Int4{Int32: domainID, Valid: true},
		Severity:        severity,
		Status:          status,
		RecordType:      nsHealthRecordType,
		Resolver1:       resolver1,
		Resolver1Result: pgtype.Text{String: result1, Valid: result1 != ""},
		Resolver2:       resolver2,
		Resolver2Result: pgtype.Text{String: result2, Valid: result2 != ""},
		Details:         pgtype.Text{String: details, Valid: details != ""},
	}); err != nil {
		a.logger.WarnContext(ctx, "failed to create dns resolution consistency finding",
			"record_type", nsHealthRecordType, "error", err)
		return fmt.Errorf(
			"create dns resolution consistency finding %s: %w",
			nsHealthRecordType,
			err,
		)
	}
	a.emitFindingObservation(
		ctx,
		observer.EntityDNSResolutionConsistencyFinding,
		NSResolverMismatch+"|"+nsHealthRecordType,
		map[string]any{
			"issue_type": NSResolverMismatch, "record_type": nsHealthRecordType,
			"resolver1": resolver1, "resolver2": resolver2,
			"severity": string(severity), "status": string(status), "details": details,
		},
	)
	return nil
}

func (a *Assessor) emitFindingObservation(
	ctx context.Context,
	entityType, entityKey string,
	payload map[string]any,
) {
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, entityType, entityKey, observer.PayloadJSON(payload),
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit finding observation",
			"entity_type", entityType, "entity_key", entityKey, "error", oErr)
	}
}
