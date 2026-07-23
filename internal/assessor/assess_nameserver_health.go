package assessor

import (
	"context"
	"net"
	"strings"

	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
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
	domain, err := a.getDomain(ctx, domainUID)
	if err != nil {
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

	ev := detect.NameserverHealthEvidence{RecordType: nsHealthRecordType}
	for _, r := range records {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Nameserver)), ".")
		probe := a.nsProber.ProbeNameserver(net.JoinHostPort(host, "53"), domain.Name, dns.TypeSOA)
		ev.Nameservers = append(ev.Nameservers, detect.NameserverProbeEvidence{
			Nameserver: r.Nameserver,
			Probed:     true,
			Reached:    probe.Reachable,
			TCPProbed:  true,
			TCPOK:      probe.TCPOK,
			HasEDNS:    probe.HasEDNS,
			LatencyMs:  int32(probe.RTT.Milliseconds()),
			ApexSerial: strings.Join(probe.Answers, " "),
		})
	}

	found, err := detect.NameserverHealthDetector{
		LatencyInfoMs:   nsLatencyInfoMs,
		LatencyLowMs:    nsLatencyLowMs,
		LatencyMediumMs: nsLatencyMediumMs,
	}.Detect(ev)
	if err != nil {
		return err
	}
	return a.reconcile(ctx, domain.Name, detect.CheckNameserverHealth, found)
}
