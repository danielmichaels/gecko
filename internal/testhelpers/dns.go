package testhelpers

import (
	"fmt"
	"github.com/miekg/dns"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// MockDNSServer represents a mock DNS server for testing
type MockDNSServer struct {
	Server     *dns.Server
	Port       int
	Records    map[string]map[uint16][]dns.RR
	mu         sync.RWMutex
	ListenAddr string
	Logger     *slog.Logger
}

// NewMockDNSServer creates a new mock DNS server
func NewMockDNSServer() (*MockDNSServer, error) {
	// Find an available port
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to find available port: %w", err)
	}

	port := listener.LocalAddr().(*net.UDPAddr).Port
	_ = listener.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	server := &MockDNSServer{
		Port:       port,
		Records:    make(map[string]map[uint16][]dns.RR),
		ListenAddr: addr,
		Logger:     slog.Default(), // fixme use this, or custom?
	}
	// clear any existing handlers and register new one
	dns.DefaultServeMux = dns.NewServeMux()
	dns.HandleFunc(".", server.handleRequest)

	s := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.DefaultServeMux,
	}

	server.Server = s

	return server, nil
}

// Start starts the mock DNS server
func (s *MockDNSServer) Start() error {
	errChan := make(chan error, 1)

	go func() {
		s.Logger.Debug("Starting mock DNS server", "address", s.ListenAddr)
		err := s.Server.ListenAndServe()
		if err != nil {
			s.Logger.Error("Mock DNS server error", "error", err)
			errChan <- err
		}
		close(errChan)
	}()

	// Give the server a moment to start
	select {
	case err := <-errChan:
		return err
	case <-time.After(100 * time.Millisecond):
		s.Logger.Debug("Mock DNS server started successfully", "address", s.ListenAddr)
		return nil
	default:
		return nil
	}
}

// Stop stops the mock DNS server
func (s *MockDNSServer) Stop() error {
	s.Logger.Debug("Stopping mock DNS server", "address", s.ListenAddr)
	return s.Server.Shutdown()
}

// AddRecord adds a DNS record to the mock server
func (s *MockDNSServer) AddRecord(name string, rrtype uint16, ttl uint32, rdata string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var rr dns.RR
	var err error

	fqdn := dns.Fqdn(name)

	switch rrtype {
	case dns.TypeA:
		rr = &dns.A{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.ParseIP(rdata),
		}
	case dns.TypeAAAA:
		rr = &dns.AAAA{
			Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: net.ParseIP(rdata),
		}
	case dns.TypeCNAME:
		rr = &dns.CNAME{
			Hdr:    dns.RR_Header{Name: fqdn, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: dns.Fqdn(rdata),
		}
	case dns.TypeTXT:
		// For TXT records, we need to handle them differently
		// The TXT record data needs to be split into chunks of 255 bytes or less
		txt := &dns.TXT{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
		}

		// If the data is longer than 255 bytes, split it into chunks
		if len(rdata) > 255 {
			var chunks []string
			for i := 0; i < len(rdata); i += 255 {
				end := i + 255
				if end > len(rdata) {
					end = len(rdata)
				}
				chunks = append(chunks, rdata[i:end])
			}
			txt.Txt = chunks
		} else {
			txt.Txt = []string{rdata}
		}

		rr = txt
	case dns.TypeMX:
		parts := strings.Fields(rdata)
		pref := uint16(10)
		mx := ""
		if len(parts) >= 2 {
			fmt.Sscanf(parts[0], "%d", &pref)
			mx = parts[1]
		} else if len(parts) == 1 {
			mx = parts[0]
		}
		rr = &dns.MX{
			Hdr:        dns.RR_Header{Name: fqdn, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
			Preference: pref,
			Mx:         dns.Fqdn(mx),
		}
	case dns.TypeNS:
		rr = &dns.NS{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
			Ns:  dns.Fqdn(rdata),
		}
	case dns.TypeSOA:
		// Parse SOA record format: primary hostmaster serial refresh retry expire minimum
		parts := strings.Fields(rdata)
		var primary, hostmaster string
		var serial, refresh, retry, expire, minimum uint32

		if len(parts) >= 7 {
			primary = parts[0]
			hostmaster = parts[1]
			fmt.Sscanf(parts[2], "%d", &serial)
			fmt.Sscanf(parts[3], "%d", &refresh)
			fmt.Sscanf(parts[4], "%d", &retry)
			fmt.Sscanf(parts[5], "%d", &expire)
			fmt.Sscanf(parts[6], "%d", &minimum)
		}

		rr = &dns.SOA{
			Hdr:     dns.RR_Header{Name: fqdn, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
			Ns:      dns.Fqdn(primary),
			Mbox:    dns.Fqdn(hostmaster),
			Serial:  serial,
			Refresh: refresh,
			Retry:   retry,
			Expire:  expire,
			Minttl:  minimum,
		}
	default:
		return fmt.Errorf("unsupported record type: %d", rrtype)
	}

	if _, ok := s.Records[fqdn]; !ok {
		s.Records[fqdn] = make(map[uint16][]dns.RR)
	}

	s.Records[fqdn][rrtype] = append(s.Records[fqdn][rrtype], rr)
	s.Logger.Debug("Added DNS record", "name", fqdn, "type", rrtype, "data", rdata)
	return err
}

// handleRequest handles DNS requests to the mock server
func (s *MockDNSServer) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	// Check for EDNS0.  Set it if it exists, otherwise, don't.
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(4096, true) // Use a larger buffer size
	}

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	s.Logger.Debug("Received DNS query", "name", q.Name, "type", q.Qtype)

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if we have records for this name and type
	if records, ok := s.Records[q.Name]; ok {
		if rrs, ok := records[q.Qtype]; ok {
			for _, rr := range rrs {
				m.Answer = append(m.Answer, rr)
			}
			s.Logger.Debug("Returning records", "name", q.Name, "type", q.Qtype, "count", len(m.Answer))
		}
	}

	// If no records found, return NXDOMAIN
	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
		s.Logger.Debug("No records found, returning NXDOMAIN", "name", q.Name, "type", q.Qtype)
	}

	err := w.WriteMsg(m)
	if err != nil {
		s.Logger.Error("Failed to write DNS response", "error", err)
	}
}

// ClearRecords removes all DNS records from the mock server in a thread-safe way
func (s *MockDNSServer) ClearRecords() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Records = make(map[string]map[uint16][]dns.RR)
}
