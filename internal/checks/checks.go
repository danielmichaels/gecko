package checks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"sync"

	"github.com/danielmichaels/gecko/internal/dnsclient"
)

type Asset struct {
	Kind     string
	Value    string
	ID       int64
	TenantID int32
}

type EvidenceScope int

const (
	SingleAsset EvidenceScope = iota
	AssetGroup
)

type Finding struct {
	IssueType string
	EntityKey string
	Severity  string
	Title     string
	Details   string
	Evidence  json.RawMessage
}

type Key struct {
	IssueType string
	EntityKey string
}

// Indeterminate protects existing findings when a check could not reach a verdict.
type DetectResult struct {
	Found         []Finding
	Indeterminate []Key
}

type Observation struct {
	EntityType string
	EntityKey  string
	Payload    json.RawMessage
}

type Collector[E any] interface {
	Kind() string
	Accepts() []string
	Collect(ctx context.Context, d Deps, a Asset) (E, error)
}

type Detector[E any] interface {
	Kind() string
	Scope() EvidenceScope
	Detect(ev E) (DetectResult, error)
}

type Deps struct {
	Resolver   dnsclient.Resolver
	HTTPProber HTTPProber
	NSProber   NameserverProber
	TLSDialer  TLSDialer
}

type ProbeResult struct {
	Body       string
	StatusCode int
	Reached    bool
}

type HTTPProber interface {
	Probe(ctx context.Context, target string) ProbeResult
	Get(ctx context.Context, url string) ProbeResult
}

type NameserverProber interface {
	ProbeNameserver(server, name string, qtype uint16) dnsclient.NSProbeResult
}

type TLSDialer interface {
	DialTLS(ctx context.Context, hostPort string) (*tls.ConnectionState, error)
}

type Registered struct {
	collect func(ctx context.Context, d Deps, a Asset) (json.RawMessage, error)
	detect  func(raw json.RawMessage) (DetectResult, error)
	Kind    string
	Accepts []string
	Scope   EvidenceScope
}

func (r *Registered) Collect(ctx context.Context, d Deps, a Asset) (json.RawMessage, error) {
	return r.collect(ctx, d, a)
}

func (r *Registered) Detect(raw json.RawMessage) (DetectResult, error) {
	return r.detect(raw)
}

var (
	mu       sync.RWMutex
	registry = map[string]*Registered{}
)

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
		detect: func(raw json.RawMessage) (DetectResult, error) {
			var ev E
			if err := json.Unmarshal(raw, &ev); err != nil {
				return DetectResult{}, err
			}
			return d.Detect(ev)
		},
	}
}

func Lookup(kind string) (*Registered, bool) {
	mu.RLock()
	defer mu.RUnlock()
	r, ok := registry[kind]
	return r, ok
}

func All() []*Registered {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]*Registered, 0, len(registry))
	for _, r := range registry {
		out = append(out, r)
	}
	return out
}
