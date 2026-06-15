package dnsclient

import (
	"time"

	"github.com/miekg/dns"
)

// nsProbeTimeout bounds a single direct nameserver exchange. It is long enough
// not to false-positive on a slow-but-alive nameserver (the medium latency tier
// is 900ms) yet short enough to surface an unreachable one promptly.
const nsProbeTimeout = 3 * time.Second

// NSProbeResult captures a direct probe of one authoritative nameserver,
// produced by ProbeNameserver. It queries a specific server address rather than
// the configured recursive resolver.
type NSProbeResult struct {
	Answers   []string      // rendered answer rdata, for cross-nameserver comparison
	RTT       time.Duration // round-trip time of the UDP query
	Rcode     int           // response code of the UDP answer
	Reachable bool          // the server answered the UDP query
	HasEDNS   bool          // the UDP response carried an EDNS0 OPT record
	TCPOK     bool          // the server also answered the same query over TCP
}

// ProbeNameserver sends a direct, non-recursive query for name/qtype to a
// specific nameserver address (host:port) over UDP (with EDNS0) and then TCP. It
// is the active primitive behind the nameserver-health assessor: it measures
// reachability, latency, EDNS0 and TCP support, and returns the answer set for
// cross-nameserver consistency comparison.
//
// Unlike the LookupX methods it bypasses the fleet L1/DB cache entirely — results
// are specific to one server and must not pollute the cache, which is keyed only
// on (qtype, fqdn). It still passes through the fleet rate limiter.
func (c *DNSClient) ProbeNameserver(server, name string, qtype uint16) NSProbeResult {
	var res NSProbeResult

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = false
	m.SetEdns0(4096, false)

	udp := &dns.Client{Net: "udp", Timeout: nsProbeTimeout}
	if c.limiter.Acquire() {
		if r, rtt, err := udp.Exchange(m, server); err == nil && r != nil {
			res.Reachable = true
			res.RTT = rtt
			res.Rcode = r.Rcode
			res.HasEDNS = r.IsEdns0() != nil
			res.Answers = processResponse(r, qtype)
		}
	}

	tcp := &dns.Client{Net: "tcp", Timeout: nsProbeTimeout}
	if c.limiter.Acquire() {
		if r, _, err := tcp.Exchange(m, server); err == nil && r != nil {
			res.TCPOK = true
		}
	}

	return res
}
