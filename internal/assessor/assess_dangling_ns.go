package assessor

import "context"

// DanglingNS is retained for readers still referencing the issue-type string; the
// canonical value lives in the detect package (detect.IssueDanglingNS).
const DanglingNS = "dangling_ns"

// AssessDanglingNS is subsumed by AssessNameserverConfig, which now collects the
// registrable-parent SOA signal and emits dangling_ns findings under the
// nameserver_config check. Kept as a no-op so its River worker stays valid until
// Phase 2 collapses the two jobs into one collector.
func (a *Assessor) AssessDanglingNS(_ context.Context, _ string) error {
	return nil
}
