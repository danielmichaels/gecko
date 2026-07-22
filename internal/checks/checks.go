// Package checks defines the collect/detect seam: the open-for-extension,
// closed-for-modification substrate for security checks. A check is a Collector
// (outbound I/O that gathers typed evidence) paired with a Detector (a pure
// function that interprets that evidence into findings). Adding a check is one
// Register call -- no migration, no worker/queue wiring, no query edit.
package checks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"sync"

	"github.com/danielmichaels/gecko/internal/dnsclient"
)

// Asset is the thing a check runs against. Phase 1 is domain-only (kind="domain",
// 1:1 with a row in domains); ip/host assets are the deferred wedge. The registry,
// evidence log, findings, and reconciler stay kind-agnostic so an ip/host collector
// lands later as pure new code.
type Asset struct {
	Kind     string
	Value    string
	ID       int64
	TenantID int32
}

// EvidenceScope is a Detector's static declaration of how much state it needs, so
// the platform can plan and batch evidence assembly. Every check today is
// SingleAsset; the cross-asset wedge (NS-reuse, shared-IP) declares a wider scope.
type EvidenceScope int

const (
	// SingleAsset: the detector reasons over one asset's own evidence.
	SingleAsset EvidenceScope = iota
	// AssetGroup: the detector reasons over a group of related assets (e.g. every
	// asset delegating to a shared nameserver set). Reserved for the NS-reuse wedge.
	AssetGroup
)

// Finding is a problem TRUE NOW for an asset+check. Compliant / not-applicable is
// modelled as the ABSENCE of a Finding (Decision A): a detector returns only the
// problems it found, never a positive "OK" row. The reconciler resolves any open
// finding a later Detect no longer returns.
type Finding struct {
	// IssueType is the stable machine identifier for the kind of problem, e.g.
	// "weak_spf_policy". Namespaced per check so it is globally unique.
	IssueType string
	// EntityKey is the sub-identity within a check that keeps sibling findings
	// distinct: a DKIM selector, a nameserver, an email auth_type, or "" when the
	// check has at most one finding per asset. Part of the finding identity key.
	EntityKey string
	Severity  string
	Title     string
	Details   string
	// Evidence is the slice of collected evidence that justifies this finding,
	// stored on the finding row for display and audit.
	Evidence json.RawMessage
}

// Observation is one piece of evidence a Collector records into the append-only
// evidence log. Used by the Phase 2 River wiring; detectors never see it.
type Observation struct {
	EntityType string
	EntityKey  string
	Payload    json.RawMessage
}

// Collector gathers evidence for one asset via outbound I/O. It is impure,
// deps-carrying, and adaptive (DKIM selector fan-out, CNAME chain walk). Its typed
// evidence E is serialized into the evidence log and handed to the paired Detector.
type Collector[E any] interface {
	Kind() string
	// Accepts reports the asset kinds this collector runs against, e.g.
	// []string{"domain"}. A future ip collector returns []string{"ip"}.
	Accepts() []string
	Collect(ctx context.Context, d Deps, a Asset) (E, error)
}

// Detector interprets stored evidence into findings. It MUST be pure: no clock, no
// network, no DB access beyond its input. Purity is what makes findings
// table-driven-testable and re-detection over stored evidence possible.
type Detector[E any] interface {
	Kind() string
	Scope() EvidenceScope
	Detect(ev E) ([]Finding, error)
}

// Deps bundles every outbound-I/O seam a Collector may use, so each collector takes
// only what it needs and a future ip/host collector adds its own seam here without
// touching existing checks. Left nil in pure detector tests.
type Deps struct {
	Resolver   dnsclient.Resolver
	HTTPProber HTTPProber
	NSProber   NameserverProber
	TLSDialer  TLSDialer
}

// ProbeResult is the outcome of an HTTP(S) probe. Reached is false when no response
// could be obtained -- itself a signal (an unclaimed resource for a known provider).
type ProbeResult struct {
	Body       string
	StatusCode int
	Reached    bool
}

// HTTPProber probes a target over HTTP(S). Probe infers scheme and falls back
// HTTPS->HTTP; Get fetches an exact URL with no redirect following (MTA-STS policy).
type HTTPProber interface {
	Probe(ctx context.Context, target string) ProbeResult
	Get(ctx context.Context, url string) ProbeResult
}

// NameserverProber probes an authoritative nameserver directly (nameserver health).
type NameserverProber interface {
	ProbeNameserver(server, name string, qtype uint16) dnsclient.NSProbeResult
}

// TLSDialer opens a TLS connection and returns its handshake state, the seam for
// certificate collection (§4.7 -- previously an un-faked tls.DialWithDialer).
type TLSDialer interface {
	DialTLS(ctx context.Context, hostPort string) (*tls.ConnectionState, error)
}

// Registered is a type-erased view of one collect/detect pair, so the runtime can
// drive heterogeneous checks uniformly. Collect and Detect route evidence through
// JSON -- the same boundary the evidence log stores it behind -- so a check that
// round-trips here is guaranteed to round-trip through the log.
type Registered struct {
	collect func(ctx context.Context, d Deps, a Asset) (json.RawMessage, error)
	detect  func(raw json.RawMessage) ([]Finding, error)
	Kind    string
	Accepts []string
	Scope   EvidenceScope
}

// Collect runs the collector and returns its evidence as canonical JSON.
func (r *Registered) Collect(ctx context.Context, d Deps, a Asset) (json.RawMessage, error) {
	return r.collect(ctx, d, a)
}

// Detect runs the pure detector over already-collected evidence JSON.
func (r *Registered) Detect(raw json.RawMessage) ([]Finding, error) {
	return r.detect(raw)
}

var (
	mu       sync.RWMutex
	registry = map[string]*Registered{}
)

// Register wires a Collector+Detector pair under their shared Kind. This one call
// is the entire cost of adding a check. Panics on a kind mismatch or a duplicate
// registration -- both are programmer errors caught at init.
func Register[E any](c Collector[E], d Detector[E]) {
	if c.Kind() != d.Kind() {
		panic("checks: collector/detector kind mismatch: " + c.Kind() + " != " + d.Kind())
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[c.Kind()]; dup {
		panic("checks: duplicate registration for kind " + c.Kind())
	}
	registry[c.Kind()] = &Registered{
		Kind:    c.Kind(),
		Accepts: c.Accepts(),
		Scope:   d.Scope(),
		collect: func(ctx context.Context, dp Deps, a Asset) (json.RawMessage, error) {
			ev, err := c.Collect(ctx, dp, a)
			if err != nil {
				return nil, err
			}
			return json.Marshal(ev)
		},
		detect: func(raw json.RawMessage) ([]Finding, error) {
			var ev E
			if err := json.Unmarshal(raw, &ev); err != nil {
				return nil, err
			}
			return d.Detect(ev)
		},
	}
}

// Lookup returns the registered check for a kind.
func Lookup(kind string) (*Registered, bool) {
	mu.RLock()
	defer mu.RUnlock()
	r, ok := registry[kind]
	return r, ok
}

// All returns every registered check. Order is unspecified.
func All() []*Registered {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]*Registered, 0, len(registry))
	for _, r := range registry {
		out = append(out, r)
	}
	return out
}
