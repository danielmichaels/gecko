package dnsclient

import (
	"time"

	"github.com/miekg/dns"
)

// nsProbeTimeout allows the 900ms latency tier without delaying unreachable probes.
const nsProbeTimeout = 3 * time.Second

// NSProbeResult captures a direct authoritative nameserver probe.
// Attempted fields distinguish shed probes from failed exchanges.
type NSProbeResult struct {
	Answers      []string      // rendered answer rdata, for cross-nameserver comparison
	RTT          time.Duration // round-trip time of the UDP query
	Rcode        int           // response code of the UDP answer
	Attempted    bool          // the UDP exchange was actually issued
	Reachable    bool          // the server answered the UDP query
	HasEDNS      bool          // the UDP response carried an EDNS0 OPT record
	TCPAttempted bool          // the TCP exchange was actually issued
	TCPOK        bool          // the server also answered the same query over TCP
}

// ProbeNameserver queries one server over UDP and TCP.
// Server-specific results bypass the shared cache but use the fleet limiter.
func (c *DNSClient) ProbeNameserver(server, name string, qtype uint16) NSProbeResult {
	var res NSProbeResult

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = false
	m.SetEdns0(4096, false)

	udp := &dns.Client{Net: "udp", Timeout: nsProbeTimeout}
	if c.limiter.Acquire() {
		res.Attempted = true
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
		res.TCPAttempted = true
		if r, _, err := tcp.Exchange(m, server); err == nil && r != nil {
			res.TCPOK = true
		}
	}

	return res
}
