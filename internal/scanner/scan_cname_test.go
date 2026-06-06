package scanner

import (
	"log/slog"
	"testing"
)

func TestScanCNAMEUsesInjectedResolver(t *testing.T) {
	fake := &fakeResolver{cnameReturn: []string{"target.example.com."}, cnameOK: true}
	s := NewScanner(Config{Logger: slog.Default(), Resolver: fake})

	_ = s.ScanCNAME("app.example.com")

	if len(fake.calledCNAME) == 0 {
		t.Fatal("ScanCNAME did not route through the injected resolver")
	}
}
