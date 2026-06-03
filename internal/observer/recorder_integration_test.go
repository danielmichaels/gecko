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
		if err := pc.Pool.QueryRow(
			ctx,
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
		t.Errorf(
			"after indeterminate scan, projection = %v, want [1.1.1.1] (no phantom delete)",
			got,
		)
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

// TestNoLegacyHistoryTablesRemain asserts the shadow-table audit pattern is fully
// decommissioned: after all migrations (incl. 00008 + 00009) no *_history table
// survives, while the live projection tables and updated_at_trigger do.
func TestNoLegacyHistoryTablesRemain(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	var historyTables int
	if err := pc.Pool.QueryRow(
		ctx,
		`SELECT count(*) FROM information_schema.tables
		 WHERE table_schema='public' AND table_name LIKE '%\_history'`,
	).Scan(&historyTables); err != nil {
		t.Fatalf("count history tables: %v", err)
	}
	if historyTables != 0 {
		t.Errorf("expected 0 *_history tables after migrations, got %d", historyTables)
	}

	// Sanity: a live projection table and the kept updated_at_trigger remain.
	var liveTables, updatedAtFn int
	if err := pc.Pool.QueryRow(
		ctx,
		`SELECT count(*) FROM information_schema.tables
		 WHERE table_schema='public' AND table_name='a_records'`,
	).Scan(&liveTables); err != nil {
		t.Fatalf("count a_records: %v", err)
	}
	if liveTables != 1 {
		t.Errorf("expected live a_records table to remain, got %d", liveTables)
	}
	if err := pc.Pool.QueryRow(
		ctx,
		`SELECT count(*) FROM pg_proc WHERE proname='updated_at_trigger'`,
	).Scan(&updatedAtFn); err != nil {
		t.Fatalf("count updated_at_trigger: %v", err)
	}
	if updatedAtFn != 1 {
		t.Errorf("expected updated_at_trigger() to remain, got %d", updatedAtFn)
	}
}

// TestRecorderRecordSRV exercises a rich type whose key (target|port|priority)
// excludes a mutable field (weight): a weight change behind the same key must be
// an "updated", not a delete+create.
func TestRecorderRecordSRV(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	const tenantID = int32(1)
	d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       "srv.example.com",
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
		TenantID: tenantID, DomainID: d.ID, DomainUID: d.Uid, DomainName: d.Name, ScanID: scan.ID,
	}
	record := func(entries []string) {
		t.Helper()
		tx, err := pc.Pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		rec := observer.New(pc.Queries.WithTx(tx))
		if err := rec.RecordSRV(ctx, ident, entries, true); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("RecordSRV: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	obsCount := func(changeType string) int {
		var n int
		if err := pc.Pool.QueryRow(
			ctx,
			`SELECT count(*) FROM domain_observations
			 WHERE domain_name=$1 AND entity_type=$2 AND change_type=$3`,
			d.Name, observer.EntitySRVRecord, changeType,
		).Scan(&n); err != nil {
			t.Fatalf("count observations: %v", err)
		}
		return n
	}
	currentWeight := func() int {
		var w int
		if err := pc.Pool.QueryRow(
			ctx,
			`SELECT weight FROM srv_records WHERE domain_id=$1`, d.ID,
		).Scan(&w); err != nil {
			t.Fatalf("query srv weight: %v", err)
		}
		return w
	}

	// entry format is "target port weight priority" (as dnsclient formats SRV).
	record([]string{"sip.example.com. 5060 10 20"})
	if c := obsCount(observer.ChangeCreated); c != 1 {
		t.Errorf("created = %d, want 1", c)
	}

	// Same key (target|port|priority), changed weight -> updated, not create/delete.
	record([]string{"sip.example.com. 5060 99 20"})
	if c := obsCount(observer.ChangeUpdated); c != 1 {
		t.Errorf("updated = %d, want 1", c)
	}
	if c := obsCount(observer.ChangeCreated); c != 1 {
		t.Errorf("created should stay 1, got %d", c)
	}
	if c := obsCount(observer.ChangeDeleted); c != 0 {
		t.Errorf("deleted should be 0 (weight change is an update), got %d", c)
	}
	if w := currentWeight(); w != 99 {
		t.Errorf("projection weight = %d, want 99 (updated in place)", w)
	}

	// Authoritative empty -> the record is deleted.
	record(nil)
	if c := obsCount(observer.ChangeDeleted); c != 1 {
		t.Errorf("deleted = %d, want 1", c)
	}
}

// TestRecordFindingChange_SuppressesNoOpObservations proves the finding/attempt
// path matches the DNS-record path: re-observing an unchanged payload emits NO
// observation, only a genuine change does. This is what keeps the append-only
// log free of per-scan noise.
func TestRecordFindingChange_SuppressesNoOpObservations(t *testing.T) {
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	const tenantID = int32(1)
	d, err := pc.Queries.DomainsInsert(ctx, store.DomainsInsertParams{
		TenantID:   pgtype.Int4{Int32: tenantID, Valid: true},
		Name:       "find.example.com",
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
		TenantID: tenantID, DomainID: d.ID, DomainUID: d.Uid, DomainName: d.Name, ScanID: scan.ID,
	}

	const entityKey = "soft_fail_spf_policy"
	record := func(payload []byte) {
		t.Helper()
		tx, err := pc.Pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			t.Fatalf("begin tx: %v", err)
		}
		rec := observer.New(pc.Queries.WithTx(tx))
		if err := rec.RecordFindingChange(ctx, ident, observer.EntitySPFFinding, entityKey, payload); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("RecordFindingChange: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	obsCount := func(changeType string) int {
		var n int
		if err := pc.Pool.QueryRow(
			ctx,
			`SELECT count(*) FROM domain_observations
			 WHERE tenant_id=$1 AND domain_name=$2 AND entity_type=$3 AND entity_key=$4 AND change_type=$5`,
			tenantID, d.Name, observer.EntitySPFFinding, entityKey, changeType,
		).Scan(&n); err != nil {
			t.Fatalf("count observations: %v", err)
		}
		return n
	}

	open := observer.PayloadJSON(map[string]any{
		"issue_type": entityKey, "severity": "medium", "status": "open",
		"value": "v=spf1 ~all", "details": "soft fail",
	})

	// First sighting -> created.
	record(open)
	if c := obsCount(observer.ChangeCreated); c != 1 {
		t.Errorf("after first sighting, created = %d, want 1", c)
	}

	// Re-observed unchanged -> NO new observation.
	record(open)
	if c := obsCount(observer.ChangeCreated); c != 1 {
		t.Errorf("identical re-observation must not emit; created = %d, want 1", c)
	}
	if c := obsCount(observer.ChangeUpdated); c != 0 {
		t.Errorf("identical re-observation must not emit updated; updated = %d, want 0", c)
	}

	// Genuine change -> updated.
	changed := observer.PayloadJSON(map[string]any{
		"issue_type": entityKey, "severity": "high", "status": "open",
		"value": "v=spf1 -all", "details": "hard fail now",
	})
	record(changed)
	if c := obsCount(observer.ChangeUpdated); c != 1 {
		t.Errorf("genuine change must emit updated; updated = %d, want 1", c)
	}
	if c := obsCount(observer.ChangeCreated); c != 1 {
		t.Errorf("created should stay 1, got %d", c)
	}
}
