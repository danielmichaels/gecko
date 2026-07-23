package assessor

import (
	"context"
	"net"
	"strings"

	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

const (
	// longChainThreshold and maxChainDepth bound CNAME chain-hygiene analysis.
	longChainThreshold = 8
	maxChainDepth      = 16
	// probeConcurrency bounds concurrent outbound CNAME-target probes per assess.
	probeConcurrency = 4
)

// AssessCNAMEDangling reads the domain's persisted CNAME records, re-resolves each
// target live to detect non-resolving (NXDOMAIN) targets, fingerprints
// takeover-able providers, and — for resolving takeover candidates — probes the
// target over HTTP(S) to confirm or suppress the finding. It records dangling
// findings and CNAME chain-hygiene findings with observations.
func (a *Assessor) AssessCNAMEDangling(ctx context.Context, domainUID string) error {
	domain, err := a.getDomain(ctx, domainUID)
	if err != nil {
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

	// Each target's live lookups + conditional HTTP probe are independent; fan out
	// with a bounded worker pool and index-assign to keep evidence order stable.
	ev := detect.CNAMEEvidence{Targets: make([]detect.CNAMETargetEvidence, len(records))}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(probeConcurrency)
	for i, record := range records {
		g.Go(func() error {
			ev.Targets[i] = a.collectCNAMETarget(gctx, record)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	res, err := detect.CNAMEDetector{LongChainThreshold: longChainThreshold}.Detect(ev)
	if err != nil {
		return err
	}
	return a.reconcile(ctx, domain.ID, domain.Name, detect.CheckCNAME, res)
}

// collectCNAMETarget gathers one CNAME target's live resolution, takeover-provider
// fingerprint, conditional HTTP probe, and chain-hygiene facts into evidence. The
// probe fires only for a takeover-able provider that still resolves -- the only
// case the verdict consults it (matching the pre-refactor short-circuit).
func (a *Assessor) collectCNAMETarget(
	ctx context.Context,
	record store.CnameRecords,
) detect.CNAMETargetEvidence {
	target := record.Target
	_, res := a.dnsClient.LookupWithStatus(target, dns.TypeA)
	fp, fpMatched := matchFingerprint(target)

	t := detect.CNAMETargetEvidence{
		Target:           target,
		ResolutionStatus: resolutionString(res),
		FPMatched:        fpMatched,
		IsIPLiteral:      net.ParseIP(strings.TrimSuffix(target, ".")) != nil,
	}
	if fpMatched {
		t.Provider = fp.Provider
		t.TakeoverProvider = fp.TakeoverPossible
		t.FPErrorBody = fp.ErrorBody
	}
	if fpMatched && fp.TakeoverPossible && res == dnsclient.ResolutionData {
		probe := a.prober.Probe(ctx, target)
		t.ProbeReached = probe.Reached
		t.ProbeStatusCode = probe.StatusCode
		t.ProbeBody = probe.Body
	}
	length, looped := a.walkCNAMEChain(record.Target)
	t.ChainLength = length
	t.ChainLooped = looped
	return t
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
