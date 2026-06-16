package service

import (
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// rule builds a silence-rule suppression row. domainID <= 0 means tenant-global.
func rule(domainID int32, kind, issueType string, expires *time.Time) store.FindingSuppressions {
	s := store.FindingSuppressions{
		Kind:      pgtype.Text{String: kind, Valid: true},
		IssueType: pgtype.Text{String: issueType, Valid: true},
		State:     store.SuppressionStateSilenced,
	}
	if domainID > 0 {
		s.DomainID = pgtype.Int4{Int32: domainID, Valid: true}
	}
	if expires != nil {
		s.ExpiresAt = pgtype.Timestamptz{Time: *expires, Valid: true}
	}
	return s
}

// ack builds a per-finding acknowledgement row.
func ack(domainID int32, findingUID string, expires *time.Time) store.FindingSuppressions {
	s := store.FindingSuppressions{
		DomainID:   pgtype.Int4{Int32: domainID, Valid: true},
		FindingUid: pgtype.Text{String: findingUID, Valid: true},
		State:      store.SuppressionStateAcknowledged,
	}
	if expires != nil {
		s.ExpiresAt = pgtype.Timestamptz{Time: *expires, Valid: true}
	}
	return s
}

func TestSuppressionMatches(t *testing.T) {
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name       string
		s          store.FindingSuppressions
		domainID   int32
		kind       string
		issueType  string
		findingUID string
		want       bool
	}{
		{
			name:     "tenant-global rule matches any domain",
			s:        rule(0, "NS_CONFIG", "insufficient_nameservers", nil),
			domainID: 42, kind: "NS_CONFIG", issueType: "insufficient_nameservers",
			want: true,
		},
		{
			name:     "tenant-global rule matches a different domain too",
			s:        rule(0, "NS_CONFIG", "insufficient_nameservers", nil),
			domainID: 7, kind: "NS_CONFIG", issueType: "insufficient_nameservers",
			want: true,
		},
		{
			name:     "per-domain rule matches its domain",
			s:        rule(42, "NS_CONFIG", "insufficient_nameservers", nil),
			domainID: 42, kind: "NS_CONFIG", issueType: "insufficient_nameservers",
			want: true,
		},
		{
			name:     "per-domain rule does not match a sibling domain",
			s:        rule(42, "NS_CONFIG", "insufficient_nameservers", nil),
			domainID: 43, kind: "NS_CONFIG", issueType: "insufficient_nameservers",
			want: false,
		},
		{
			name:     "rule requires matching issue_type",
			s:        rule(0, "NS_CONFIG", "insufficient_nameservers", nil),
			domainID: 42, kind: "NS_CONFIG", issueType: "same_provider",
			want: false,
		},
		{
			name:     "rule requires matching kind (same issue_type, different kind)",
			s:        rule(0, "MIN_RECORDS", "insufficient_nameservers", nil),
			domainID: 42, kind: "NS_CONFIG", issueType: "insufficient_nameservers",
			want: false,
		},
		{
			name:     "ack matches the finding uid",
			s:        ack(42, "spf_abc123", nil),
			domainID: 42, kind: "SPF", issueType: "missing_spf", findingUID: "spf_abc123",
			want: true,
		},
		{
			name:     "ack does not match a different finding uid",
			s:        ack(42, "spf_abc123", nil),
			domainID: 42, kind: "SPF", issueType: "missing_spf", findingUID: "spf_zzz999",
			want: false,
		},
		{
			name:     "expired rule never matches",
			s:        rule(0, "NS_CONFIG", "insufficient_nameservers", &past),
			domainID: 42, kind: "NS_CONFIG", issueType: "insufficient_nameservers",
			want: false,
		},
		{
			name:     "not-yet-expired (future) rule matches",
			s:        rule(0, "NS_CONFIG", "insufficient_nameservers", &future),
			domainID: 42, kind: "NS_CONFIG", issueType: "insufficient_nameservers",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := suppressionMatches(tt.s, now, tt.domainID, tt.kind, tt.issueType, tt.findingUID)
			if got != tt.want {
				t.Fatalf("suppressionMatches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAnySuppressionMatches(t *testing.T) {
	now := time.Now()
	sups := []store.FindingSuppressions{
		rule(0, "ZONE", "zone_transfer_exposed", nil),
		ack(5, "cert_xyz", nil),
	}
	if !anySuppressionMatches(sups, now, 99, "ZONE", "zone_transfer_exposed", "") {
		t.Error("expected tenant-global ZONE rule to match")
	}
	if !anySuppressionMatches(sups, now, 5, "CERT", "certificate_expiry", "cert_xyz") {
		t.Error("expected ack to match by uid")
	}
	if anySuppressionMatches(sups, now, 5, "DKIM", "missing_dkim", "dkim_other") {
		t.Error("expected no match for an unrelated finding")
	}
}
