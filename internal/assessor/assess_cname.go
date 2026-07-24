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

// AssessCNAMEDangling checks CNAME targets for takeover and chain-hygiene issues.
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

	// Index assignment preserves record order across concurrent probes.
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

// collectCNAMETarget probes only resolving takeover candidates.
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
	length, looped, status := a.walkCNAMEChain(record.Target)
	t.ChainLength = length
	t.ChainLooped = looped
	t.ChainStatus = resolutionString(status)
	return t
}

// walkCNAMEChain marks incomplete walks indeterminate.
func (a *Assessor) walkCNAMEChain(
	start string,
) (int, bool, dnsclient.ResolutionStatus) {
	seen := make(map[string]bool)
	current := start
	for length := 1; length <= maxChainDepth; length++ {
		key := strings.ToLower(strings.TrimSuffix(current, "."))
		if seen[key] {
			return length, true, dnsclient.ResolutionData
		}
		seen[key] = true
		next, status := a.dnsClient.LookupWithStatus(current, dns.TypeCNAME)
		if status == dnsclient.ResolutionIndeterminate {
			return length, false, status
		}
		if len(next) == 0 {
			return length, false, dnsclient.ResolutionEmpty
		}
		current = next[0]
	}
	// Reaching the limit does not prove the chain is loop-free.
	return maxChainDepth, false, dnsclient.ResolutionIndeterminate
}
