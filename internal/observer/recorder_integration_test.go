package observer_test

import (
	"context"
	"testing"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// TestRecorderRecordA exercises the recorder end-to-end against a real database:
// the projection stays in sync, observations are emitted with the right
// change_type, and — critically — an indeterminate resolution never deletes.
func TestRecorderRecordA(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	const tenantID = int32(1)
	d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       "rec.example.com",
		DomainType: store.DomainTypeSubdomain,
		Source:     store.DomainSourceUserSupplied,
		Status:     store.DomainStatusActive,
	})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	scan, err := pc.Queries.ScansCreate(ctx, store.ScansCreateParams{
		TenantID:   tenantID,
		DomainID:   pgtype.Int4{Int32: d.ID, Valid: true},
		DomainUid:  d.Uid,
		DomainName: d.Name,
		Source:     store.DomainSourceUserSupplied,
	})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	ident := observer.DomainIdentity{
		TenantID:   tenantID,
		DomainID:   d.ID,
		DomainUID:  d.Uid,
		DomainName: d.Name,
		ScanID:     scan.ID,
	}

	record := func(ips []string, authoritative bool) {
		t.Helper()
		tx, err := pc.Pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		rec := observer.New(pc.Queries.WithTx(tx))
		if err := rec.RecordA(ctx, ident, ips, authoritative); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("RecordA: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	currentIPs := func() []string {
		rows, err := pc.Pool.Query(ctx,
			`SELECT ipv4_address FROM a_records WHERE domain_id=$1 ORDER BY ipv4_address`, d.ID)
		if err != nil {
			t.Fatalf("query a_records: %v", err)
		}
		defer rows.Close()
		var ips []string
		for rows.Next() {
			var ip string
			if err := rows.Scan(&ip); err != nil {
				t.Fatalf("scan: %v", err)
			}
			ips = append(ips, ip)
		}
		return ips
	}
	obsCount := func(changeType string) int {
		var n int
		if err := pc.Pool.QueryRow(ctx,
			`SELECT count(*) FROM domain_observations
			 WHERE tenant_id=$1 AND domain_name=$2 AND entity_type=$3 AND change_type=$4`,
			tenantID, d.Name, observer.EntityARecord, changeType,
		).Scan(&n); err != nil {
			t.Fatalf("count observations: %v", err)
		}
		return n
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// Scan 1: first observation of two IPs, authoritative.
	record([]string{"1.1.1.1", "2.2.2.2"}, true)
	if got := currentIPs(); !eq(got, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Errorf("after scan 1, projection = %v, want [1.1.1.1 2.2.2.2]", got)
	}
	if c := obsCount(observer.ChangeCreated); c != 2 {
		t.Errorf("created observations = %d, want 2", c)
	}

	// Scan 2: 2.2.2.2 disappears, authoritative -> deleted.
	record([]string{"1.1.1.1"}, true)
	if got := currentIPs(); !eq(got, []string{"1.1.1.1"}) {
		t.Errorf("after scan 2, projection = %v, want [1.1.1.1]", got)
	}
	if c := obsCount(observer.ChangeDeleted); c != 1 {
		t.Errorf("deleted observations = %d, want 1", c)
	}

	// Scan 3: indeterminate resolution (empty observed, NOT authoritative). The
	// projection must be untouched and NO deletion may be emitted (no phantom
	// deletes on a transient SERVFAIL).
	record(nil, false)
	if got := currentIPs(); !eq(got, []string{"1.1.1.1"}) {
		t.Errorf("after indeterminate scan, projection = %v, want [1.1.1.1] (no phantom delete)", got)
	}
	if c := obsCount(observer.ChangeDeleted); c != 1 {
		t.Errorf("deleted observations after indeterminate = %d, want still 1", c)
	}

	// Scan 4: authoritative empty (NXDOMAIN/NODATA) -> the remaining IP is deleted.
	record(nil, true)
	if got := currentIPs(); len(got) != 0 {
		t.Errorf("after authoritative-empty scan, projection = %v, want []", got)
	}
	if c := obsCount(observer.ChangeDeleted); c != 2 {
		t.Errorf("deleted observations = %d, want 2", c)
	}
	if c := obsCount(observer.ChangeCreated); c != 2 {
		t.Errorf("created observations unexpectedly changed = %d, want 2", c)
	}
}
