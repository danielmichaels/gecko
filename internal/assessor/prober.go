package assessor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	probeTimeout    = 5 * time.Second
	probeBodyMaxLen = 8 << 10
)

// ProbeResult is the outcome of an HTTP/HTTPS probe of a CNAME target. Reached is
// false when no HTTP response could be obtained (connection refused, DNS failure,
// timeout) — itself a strong "unclaimed resource" signal for a known provider.
type ProbeResult struct {
	Body       string
	StatusCode int
	Reached    bool
}

// HTTPProber probes a CNAME target over HTTP(S). It is an interface so the
// assessor can be unit-tested with a deterministic fake instead of real egress.
// Get fetches an exact HTTPS URL (used for the MTA-STS policy file); it follows
// no redirects and reads a bounded body prefix.
type HTTPProber interface {
	Probe(ctx context.Context, target string) ProbeResult
	Get(ctx context.Context, url string) ProbeResult
}

type httpProber struct {
	client *http.Client
}

// newHTTPProber builds the default prober: a short timeout and redirects stopped
// at the first hop, so the immediate status/body of the target is observed rather
// than wherever a takeover landing page forwards to.
func newHTTPProber() *httpProber {
	return &httpProber{
		client: &http.Client{
			Timeout: probeTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Probe tries HTTPS then HTTP, returning the first response it reaches. A bounded
// body prefix is read so a large landing page cannot exhaust memory.
func (p *httpProber) Probe(ctx context.Context, target string) ProbeResult {
	host := strings.TrimSuffix(target, ".")
	for _, scheme := range []string{"https://", "http://"} {
		if res, ok := p.do(ctx, scheme+host); ok {
			return res
		}
	}
	return ProbeResult{Reached: false}
}

// Get fetches an exact URL (no scheme inference, no HTTP fallback), returning the
// bounded response. Used for the MTA-STS policy file, which must be retrieved over
// HTTPS at a fixed path with redirects suppressed.
func (p *httpProber) Get(ctx context.Context, url string) ProbeResult {
	res, _ := p.do(ctx, url)
	return res
}

func (p *httpProber) do(ctx context.Context, url string) (ProbeResult, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ProbeResult{}, false
	}
	res, err := p.client.Do(req)
	if err != nil {
		return ProbeResult{}, false
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, probeBodyMaxLen))
	return ProbeResult{Reached: true, StatusCode: res.StatusCode, Body: string(body)}, true
}
