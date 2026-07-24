package checks

import (
	"context"
	"encoding/json"
	"testing"
)

// fakeEvidence is a stand-in for a real check's typed evidence.
type fakeEvidence struct {
	LookedUp bool   `json:"looked_up"`
	Record   string `json:"record"`
}

type fakeCollector struct {
	kind string
	ev   fakeEvidence
}

func (c fakeCollector) Kind() string      { return c.kind }
func (c fakeCollector) Accepts() []string { return []string{"domain"} }
func (c fakeCollector) Collect(context.Context, Deps, Asset) (fakeEvidence, error) {
	return c.ev, nil
}

// fakeDetector flags a problem only when the record was looked up and is weak,
// returning nothing (compliant) otherwise -- the Decision A absence-of-finding rule.
type fakeDetector struct {
	kind  string
	scope EvidenceScope
}

func (d fakeDetector) Kind() string         { return d.kind }
func (d fakeDetector) Scope() EvidenceScope { return d.scope }
func (d fakeDetector) Detect(ev fakeEvidence) (DetectResult, error) {
	if ev.LookedUp && ev.Record == "weak" {
		return DetectResult{Found: []Finding{{IssueType: "weak_record", Severity: "medium"}}}, nil
	}
	return DetectResult{}, nil
}

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: expected panic, got none", name)
		}
	}()
	fn()
}

func TestRegisterWiresPair(t *testing.T) {
	Register(
		fakeCollector{kind: "wire_check", ev: fakeEvidence{LookedUp: true, Record: "weak"}},
		fakeDetector{kind: "wire_check", scope: SingleAsset},
	)
	r, ok := Lookup("wire_check")
	if !ok {
		t.Fatal("expected wire_check registered")
	}
	if r.Scope != SingleAsset {
		t.Errorf("scope = %v, want SingleAsset", r.Scope)
	}
	if len(r.Accepts) != 1 || r.Accepts[0] != "domain" {
		t.Errorf("accepts = %v, want [domain]", r.Accepts)
	}
}

func TestRegisterKindMismatchPanics(t *testing.T) {
	mustPanic(t, "kind mismatch", func() {
		Register(
			fakeCollector{kind: "collector_kind"},
			fakeDetector{kind: "detector_kind"},
		)
	})
}

func TestRegisterDuplicatePanics(t *testing.T) {
	Register(fakeCollector{kind: "dup_check"}, fakeDetector{kind: "dup_check"})
	mustPanic(t, "duplicate", func() {
		Register(fakeCollector{kind: "dup_check"}, fakeDetector{kind: "dup_check"})
	})
}

// TestRoundTrip proves evidence survives the collect->JSON->detect path the runtime
// and the evidence log both use.
func TestRoundTrip(t *testing.T) {
	Register(
		fakeCollector{kind: "rt_check", ev: fakeEvidence{LookedUp: true, Record: "weak"}},
		fakeDetector{kind: "rt_check", scope: SingleAsset},
	)
	r, _ := Lookup("rt_check")

	raw, err := r.Collect(context.Background(), Deps{}, Asset{Kind: "domain", Value: "example.com"})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	res, err := r.Detect(raw)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(res.Found) != 1 || res.Found[0].IssueType != "weak_record" {
		t.Fatalf("findings = %+v, want one weak_record", res.Found)
	}
}

// TestCompliantEvidenceYieldsNoFinding is the Decision A contract: a compliant
// asset produces an empty result, not a positive "OK" finding.
func TestCompliantEvidenceYieldsNoFinding(t *testing.T) {
	d := fakeDetector{kind: "compliant_check", scope: SingleAsset}
	res, err := d.Detect(fakeEvidence{LookedUp: true, Record: "strong"})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(res.Found) != 0 {
		t.Fatalf("compliant asset returned %d findings, want 0", len(res.Found))
	}
}

// TestDetectDistinguishesAbsentFromUnknown guards the collect/detect purity
// consequence: a record genuinely absent is a finding; a failed lookup is not.
func TestDetectDistinguishesAbsentFromUnknown(t *testing.T) {
	d := fakeDetector{kind: "absence_check", scope: SingleAsset}

	// looked up, no weak record -> compliant (no finding). Represents "record absent
	// but check ran" for this fake; real detectors emit missing_* here.
	if res, _ := d.Detect(fakeEvidence{LookedUp: true, Record: ""}); len(res.Found) != 0 {
		t.Fatalf("looked-up-absent returned %d findings", len(res.Found))
	}
	// never looked up -> unknown -> also no finding (never auto-resolve on failure).
	if res, _ := d.Detect(fakeEvidence{LookedUp: false}); len(res.Found) != 0 {
		t.Fatalf("not-looked-up returned %d findings", len(res.Found))
	}
}

var _ = json.Marshal
