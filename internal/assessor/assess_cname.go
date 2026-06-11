package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

const (
	IssuePointsToIP = "points_to_ip"
	IssueLongChain  = "long_chain"
	IssueCNAMELoop  = "cname_loop"
)

const (
	// probeConcurrency bounds concurrent outbound probes within a single assess
	// job. The fleet-wide bound is the queue_assessor MaxWorkers cap; this only
	// limits fan-out across one domain's CNAME targets.
	probeConcurrency = 4
	// longChainThreshold and maxChainDepth bound CNAME chain-hygiene analysis.
	longChainThreshold = 8
	maxChainDepth      = 16
)

// danglingVerdict is the outcome of classifying one CNAME target.
type danglingVerdict struct {
	severity         store.FindingSeverity
	status           store.FindingStatus
	provider         string
	details          string
	takeoverPossible bool
	finding          bool
}

// classifyDangling applies the conservative false-positive policy to one CNAME
// target. A target pointing at a takeover-able provider is high/takeover only when
// the takeover is confirmed (the provider's unclaimed-resource error body, or the
// target failing to resolve at all); a live page suppresses the finding. A target
// that merely fails to resolve, with no takeover-able provider, is medium and not
// flagged as takeover. Anything that resolves cleanly without a takeover signal,
// or whose resolution is indeterminate (SERVFAIL/timeout), yields no finding.
func classifyDangling(
	res dnsclient.ResolutionStatus,
	fp cnameFingerprint,
	fpMatched bool,
	probe ProbeResult,
) danglingVerdict {
	nonResolving := res == dnsclient.ResolutionEmpty

	if fpMatched && fp.TakeoverPossible {
		bodyConfirmed := probe.Reached && fp.ErrorBody != "" &&
			strings.Contains(probe.Body, fp.ErrorBody)
		switch {
		case bodyConfirmed || nonResolving:
			return danglingVerdict{
				finding:          true,
				severity:         store.FindingSeverityHigh,
				status:           store.FindingStatusOpen,
				takeoverPossible: true,
				provider:         fp.Provider,
				details: fmt.Sprintf(
					"CNAME target points to %s and the resource appears unclaimed (subdomain takeover candidate)",
					fp.Provider,
				),
			}
		case probe.Reached && probe.StatusCode == 200:
			return danglingVerdict{finding: false}
		default:
			return danglingVerdict{
				finding:          true,
				severity:         store.FindingSeverityMedium,
				status:           store.FindingStatusOpen,
				takeoverPossible: false,
				provider:         fp.Provider,
				details: fmt.Sprintf(
					"CNAME target points to %s; takeover could not be confirmed",
					fp.Provider,
				),
			}
		}
	}

	if nonResolving {
		v := danglingVerdict{
			finding:          true,
			severity:         store.FindingSeverityMedium,
			status:           store.FindingStatusOpen,
			takeoverPossible: false,
			details:          "CNAME target does not resolve (NXDOMAIN)",
		}
		if fpMatched {
			v.provider = fp.Provider
		}
		return v
	}

	return danglingVerdict{finding: false}
}

// AssessCNAMEDangling reads the domain's persisted CNAME records, re-resolves each
// target live to detect non-resolving (NXDOMAIN) targets, fingerprints
// takeover-able providers, and — for resolving takeover candidates — probes the
// target over HTTP(S) to confirm or suppress the finding. It records dangling
// findings and CNAME chain-hygiene findings with observations.
func (a *Assessor) AssessCNAMEDangling(ctx context.Context, domainUID string) error {
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

	records, err := a.store.RecordsGetCNAMEByDomainID(
		ctx,
		pgtype.Int4{Int32: domain.ID, Valid: true},
	)
	if err != nil {
		a.logger.ErrorContext(ctx, "Failed to retrieve CNAME records", "error", err)
		return err
	}
	if len(records) == 0 {
		a.logger.InfoContext(ctx, "No CNAME records to assess", "domain", domain.Uid)
		return nil
	}

	var danglingFound atomic.Int64
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(probeConcurrency)
	for _, record := range records {
		g.Go(func() error {
			if a.assessCNAMETarget(gctx, domain.ID, record) {
				danglingFound.Add(1)
			}
			return nil
		})
	}
	_ = g.Wait()

	a.logger.InfoContext(ctx, "assessed CNAME records",
		"domain", domain.Uid,
		"records", len(records),
		"dangling_findings", danglingFound.Load())
	return nil
}

// assessCNAMETarget evaluates a single CNAME record for both the dangling/takeover
// risk and chain-hygiene issues, returning whether a dangling finding was
// recorded. Per-target failures are logged, not propagated, so one bad target does
// not abort the others.
func (a *Assessor) assessCNAMETarget(
	ctx context.Context,
	domainID int32,
	record store.CnameRecords,
) bool {
	target := record.Target
	_, res := a.dnsClient.LookupWithStatus(target, dns.TypeA)

	fp, fpMatched := matchFingerprint(target)
	var probe ProbeResult
	if fpMatched && fp.TakeoverPossible && res == dnsclient.ResolutionData {
		probe = a.prober.Probe(ctx, target)
	}

	var recorded bool
	if verdict := classifyDangling(res, fp, fpMatched, probe); verdict.finding {
		recorded = a.recordDanglingFinding(ctx, domainID, target, verdict)
	}

	a.assessCNAMEChain(ctx, domainID, record)
	return recorded
}

func (a *Assessor) recordDanglingFinding(
	ctx context.Context,
	domainID int32,
	target string,
	verdict danglingVerdict,
) bool {
	_, err := a.store.StoreDanglingCnameFinding(ctx, store.StoreDanglingCnameFindingParams{
		DomainID:         pgtype.Int4{Int32: domainID, Valid: true},
		Severity:         verdict.severity,
		Status:           verdict.status,
		TargetDomain:     target,
		ServiceProvider:  pgtype.Text{String: verdict.provider, Valid: verdict.provider != ""},
		TakeoverPossible: verdict.takeoverPossible,
		Details:          pgtype.Text{String: verdict.details, Valid: verdict.details != ""},
	})
	if err != nil {
		a.logger.ErrorContext(ctx, "Failed to store dangling CNAME finding",
			"target", target, "error", err)
		return false
	}
	payload := observer.PayloadJSON(map[string]any{
		"target_domain":     target,
		"severity":          string(verdict.severity),
		"status":            string(verdict.status),
		"service_provider":  verdict.provider,
		"takeover_possible": verdict.takeoverPossible,
	})
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, observer.EntityCNAMEDanglingFinding, target, payload,
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit dangling CNAME finding observation",
			"target", target, "error", oErr)
	}
	return true
}

// assessCNAMEChain flags CNAME chain-hygiene issues: a target that is an IP
// literal, an over-long chain, or a loop.
func (a *Assessor) assessCNAMEChain(
	ctx context.Context,
	domainID int32,
	record store.CnameRecords,
) {
	target := strings.TrimSuffix(record.Target, ".")
	if net.ParseIP(target) != nil {
		a.recordRedirectionFinding(ctx, domainID, record, IssuePointsToIP,
			store.FindingSeverityMedium, 1,
			fmt.Sprintf("CNAME target %q is an IP address; a CNAME must point to a name", target))
		return
	}

	length, looped := a.walkCNAMEChain(record.Target)
	switch {
	case looped:
		a.recordRedirectionFinding(ctx, domainID, record, IssueCNAMELoop,
			store.FindingSeverityMedium, length, "CNAME chain forms a loop")
	case length >= longChainThreshold:
		a.recordRedirectionFinding(ctx, domainID, record, IssueLongChain,
			store.FindingSeverityLow, length,
			fmt.Sprintf("CNAME chain is %d hops long", length))
	}
}

// walkCNAMEChain follows the CNAME chain from start, returning the hop count and
// whether a loop was detected. The walk is bounded by maxChainDepth.
func (a *Assessor) walkCNAMEChain(start string) (int, bool) {
	seen := make(map[string]bool)
	current := start
	for length := 1; length <= maxChainDepth; length++ {
		key := strings.ToLower(strings.TrimSuffix(current, "."))
		if seen[key] {
			return length, true
		}
		seen[key] = true
		next, ok := a.dnsClient.LookupCNAME(current)
		if !ok || len(next) == 0 {
			return length, false
		}
		current = next[0]
	}
	return maxChainDepth, false
}

func (a *Assessor) recordRedirectionFinding(
	ctx context.Context,
	domainID int32,
	record store.CnameRecords,
	issueType string,
	severity store.FindingSeverity,
	chainLength int,
	details string,
) {
	_, err := a.store.StoreCnameRedirectionFinding(ctx, store.StoreCnameRedirectionFindingParams{
		DomainID:      pgtype.Int4{Int32: domainID, Valid: true},
		CnameRecordID: pgtype.Int4{Int32: record.ID, Valid: true},
		Severity:      severity,
		Status:        store.FindingStatusOpen,
		IssueType:     issueType,
		ChainLength:   pgtype.Int4{Int32: int32(chainLength), Valid: true},
		Details:       pgtype.Text{String: details, Valid: details != ""},
	})
	if err != nil {
		a.logger.ErrorContext(ctx, "Failed to store CNAME redirection finding",
			"issue_type", issueType, "error", err)
		return
	}
	payload := observer.PayloadJSON(map[string]any{
		"issue_type":   issueType,
		"severity":     string(severity),
		"status":       string(store.FindingStatusOpen),
		"chain_length": chainLength,
		"details":      details,
	})
	if oErr := observer.New(a.store).RecordFindingChange(
		ctx, a.identity, observer.EntityCNAMERedirectionFinding, issueType, payload,
	); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit CNAME redirection finding observation",
			"issue_type", issueType, "error", oErr)
	}
}
