package detect

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/dnsrecords"
)

func ztData(records ...dnsrecords.SerializedRecord) json.RawMessage {
	td := dnsrecords.ZoneTransferData{
		Records:      dnsrecords.RecordCollection{AXFR: records},
		RecordCounts: dnsrecords.RecordCount{AXFR: len(records), Total: len(records)},
	}
	b, _ := json.Marshal(td)
	return b
}

func txtRecord(name string, values ...string) dnsrecords.SerializedRecord {
	vals := make([]any, len(values))
	for i, v := range values {
		vals[i] = v
	}
	return dnsrecords.SerializedRecord{Type: "TXT", Name: name, Data: map[string]any{"txt": vals}}
}

func TestZoneTransferRefusedYieldsNothing(t *testing.T) {
	detRes, err := ZoneTransferDetector{}.Detect(ZoneTransferEvidence{
		Attempts: []ZoneTransferAttemptEvidence{
			{Nameserver: "ns1.example.com:53", TransferType: "AXFR", Successful: false},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := detRes.Found
	if len(got) != 0 {
		t.Fatalf("refused transfer produced %d findings, want 0", len(got))
	}
}

func TestZoneTransferExposed(t *testing.T) {
	got := findingsOf(ZoneTransferDetector{}.Detect(ZoneTransferEvidence{
		Attempts: []ZoneTransferAttemptEvidence{
			{
				Nameserver: "ns1.example.com:53", TransferType: "AXFR", Successful: true,
				ResponseData: ztData(
					txtRecord("_dmarc.example.com", "v=spf1 include:x contact admin@example.com"),
				),
			},
		},
	}))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.IssueType != IssueZoneTransferExposed {
		t.Errorf("issue_type = %q, want %q", f.IssueType, IssueZoneTransferExposed)
	}
	if f.EntityKey != "ns1.example.com:53" {
		t.Errorf("entity_key = %q, want the nameserver", f.EntityKey)
	}
	if f.Severity != "critical" {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if !strings.Contains(string(f.Evidence), "admin@example.com") {
		t.Errorf("evidence missing exposed email: %s", f.Evidence)
	}
}

func TestZoneTransferUnparseableStillFires(t *testing.T) {
	got := findingsOf(ZoneTransferDetector{}.Detect(ZoneTransferEvidence{
		Attempts: []ZoneTransferAttemptEvidence{
			{
				Nameserver:   "ns1.example.com:53",
				TransferType: "AXFR",
				Successful:   true,
				ResponseData: []byte("not json"),
			},
		},
	}))
	if len(got) != 1 {
		t.Fatalf(
			"unparseable-but-successful transfer produced %d findings, want 1 (the transfer succeeded)",
			len(got),
		)
	}
}

func TestZoneTransferMixedAttempts(t *testing.T) {
	got := findingsOf(ZoneTransferDetector{}.Detect(ZoneTransferEvidence{
		Attempts: []ZoneTransferAttemptEvidence{
			{
				Nameserver:   "ns1.example.com:53",
				TransferType: "AXFR",
				Successful:   true,
				ResponseData: ztData(),
			},
			{Nameserver: "ns2.example.com:53", TransferType: "AXFR", Successful: false},
		},
	}))
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 (only the successful ns)", len(got))
	}
	if got[0].EntityKey != "ns1.example.com:53" {
		t.Errorf("entity_key = %q, want ns1", got[0].EntityKey)
	}
}
