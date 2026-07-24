package findings_test

import (
	"context"
	"sync"
	"testing"

	"github.com/danielmichaels/gecko/internal/checks"
	"github.com/danielmichaels/gecko/internal/findings"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/danielmichaels/gecko/internal/testhelpers"
)

const checkKind = "test_check"

func mkFinding(issueType, entityKey, severity string) checks.Finding {
	return checks.Finding{
		IssueType: issueType, EntityKey: entityKey, Severity: severity,
		Title: "t", Details: "d",
	}
}

func TestReconcileLifecycle(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	defer pc.Close(ctx)

	const tenantID = int32(1) // seeded by test-data.sql
	asset, err := pc.Queries.AssetsUpsertDomain(ctx, store.AssetsUpsertDomainParams{
		TenantID: tenantID, Value: "recon.example.com", Source: "user_supplied",
	})
	if err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	assetID := asset.ID

	reconcile := func(finds ...checks.Finding) {
		t.Helper()
		if err := findings.Reconcile(ctx, pc.Queries, tenantID, assetID, checkKind, checks.DetectResult{Found: finds}); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	getFinding := func(issueType, entityKey string) (id int64, status string, resolved bool) {
		t.Helper()
		err := pc.Pool.QueryRow(ctx,
			`SELECT id, status, resolved_at IS NOT NULL FROM findings
			 WHERE asset_id=$1 AND check_kind=$2 AND issue_type=$3 AND entity_key=$4`,
			assetID, checkKind, issueType, entityKey).Scan(&id, &status, &resolved)
		if err != nil {
			t.Fatalf("get finding %s/%s: %v", issueType, entityKey, err)
		}
		return id, status, resolved
	}
	events := func(findingID int64) []string {
		t.Helper()
		rows, err := pc.Pool.Query(ctx,
			`SELECT event FROM findings_events WHERE finding_id=$1 ORDER BY at, id`, findingID)
		if err != nil {
			t.Fatalf("events: %v", err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var e string
			_ = rows.Scan(&e)
			out = append(out, e)
		}
		return out
	}

	a := mkFinding("issue_a", "", "high")
	b := mkFinding("issue_b", "sel1", "medium")

	// Initial open.
	reconcile(a, b)
	aID, aStatus, _ := getFinding("issue_a", "")
	bID, bStatus, _ := getFinding("issue_b", "sel1")
	if aStatus != "open" || bStatus != "open" {
		t.Fatalf("statuses = %s/%s, want open/open", aStatus, bStatus)
	}
	if got := events(aID); len(got) != 1 || got[0] != "opened" {
		t.Fatalf("a events = %v, want [opened]", got)
	}

	// Identical output preserves IDs and emits no events.
	reconcile(a, b)
	aID2, s, _ := getFinding("issue_a", "")
	if aID2 != aID || s != "open" {
		t.Fatalf("stability: id %d->%d status %s", aID, aID2, s)
	}
	if got := events(aID); len(got) != 1 {
		t.Fatalf("stability: a gained events %v (want still 1)", got)
	}
	if got := events(bID); len(got) != 1 {
		t.Fatalf("stability: b gained events %v (want still 1)", got)
	}

	// Missing findings resolve.
	reconcile(a)
	_, bStatus, bResolved := getFinding("issue_b", "sel1")
	if bStatus != "resolved" || !bResolved {
		t.Fatalf("b = %s resolved=%v, want resolved/true", bStatus, bResolved)
	}
	if _, aStatus, _ := getFinding("issue_a", ""); aStatus != "open" {
		t.Fatalf("a status = %s, want still open", aStatus)
	}
	if got := events(bID); len(got) != 2 || got[1] != "resolved" {
		t.Fatalf("b events = %v, want [opened resolved]", got)
	}

	// Returning findings reopen the same row.
	reconcile(a, b)
	bID2, bStatus, bResolved := getFinding("issue_b", "sel1")
	if bID2 != bID {
		t.Fatalf("reopen created a new row: %d != %d", bID2, bID)
	}
	if bStatus != "open" || bResolved {
		t.Fatalf("b = %s resolved=%v, want open/false", bStatus, bResolved)
	}
	if got := events(bID); len(got) != 3 || got[2] != "reopened" {
		t.Fatalf("b events = %v, want [opened resolved reopened]", got)
	}

	// Empty output resolves the scope.
	reconcile()
	if _, aStatus, _ := getFinding("issue_a", ""); aStatus != "resolved" {
		t.Fatalf("a status = %s, want resolved", aStatus)
	}
	if _, bStatus, _ := getFinding("issue_b", "sel1"); bStatus != "resolved" {
		t.Fatalf("b status = %s, want resolved", bStatus)
	}
}

func TestReconcileScopeIsolation(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	defer pc.Close(ctx)

	const tenantID = int32(1)
	asset, err := pc.Queries.AssetsUpsertDomain(ctx, store.AssetsUpsertDomainParams{
		TenantID: tenantID, Value: "scope.example.com", Source: "user_supplied",
	})
	if err != nil {
		t.Fatalf("upsert asset: %v", err)
	}

	f := mkFinding("shared_issue", "", "low")
	if err := findings.Reconcile(ctx, pc.Queries, tenantID, asset.ID, "check_one", checks.DetectResult{Found: []checks.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	// Another check cannot affect this finding.
	if err := findings.Reconcile(ctx, pc.Queries, tenantID, asset.ID, "check_two", checks.DetectResult{}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := pc.Pool.QueryRow(ctx,
		`SELECT status FROM findings WHERE asset_id=$1 AND check_kind='check_one'`, asset.ID).Scan(&status); err != nil {
		t.Fatalf("get: %v", err)
	}
	if status != "open" {
		t.Fatalf("check_one finding = %s, want open (check_two must not touch it)", status)
	}
}

func TestReconcileProtectsIndeterminate(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	defer pc.Close(ctx)

	const tenantID = int32(1)
	asset, err := pc.Queries.AssetsUpsertDomain(ctx, store.AssetsUpsertDomainParams{
		TenantID: tenantID, Value: "indet.example.com", Source: "user_supplied",
	})
	if err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	const kind = "indet_check"
	key := checks.Key{IssueType: "issue_x", EntityKey: "e1"}

	statusOf := func() string {
		t.Helper()
		var status string
		if err := pc.Pool.QueryRow(ctx,
			`SELECT status FROM findings WHERE asset_id=$1 AND check_kind=$2 AND issue_type=$3 AND entity_key=$4`,
			asset.ID, kind, key.IssueType, key.EntityKey).Scan(&status); err != nil {
			t.Fatalf("get finding: %v", err)
		}
		return status
	}

	if err := findings.Reconcile(ctx, pc.Queries, tenantID, asset.ID, kind,
		checks.DetectResult{Found: []checks.Finding{mkFinding(key.IssueType, key.EntityKey, "high")}}); err != nil {
		t.Fatal(err)
	}

	if err := findings.Reconcile(ctx, pc.Queries, tenantID, asset.ID, kind,
		checks.DetectResult{Indeterminate: []checks.Key{key}}); err != nil {
		t.Fatal(err)
	}
	if s := statusOf(); s != "open" {
		t.Fatalf("indeterminate key was resolved (status=%s), want still open", s)
	}

	if err := findings.Reconcile(ctx, pc.Queries, tenantID, asset.ID, kind,
		checks.DetectResult{}); err != nil {
		t.Fatal(err)
	}
	if s := statusOf(); s != "resolved" {
		t.Fatalf("authoritatively-absent key = %s, want resolved", s)
	}
}

func TestReconcileConcurrentScope(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreateTestDatabase(ctx)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	defer pc.Close(ctx)

	const tenantID = int32(1)
	asset, err := pc.Queries.AssetsUpsertDomain(ctx, store.AssetsUpsertDomainParams{
		TenantID: tenantID, Value: "race.example.com", Source: "user_supplied",
	})
	if err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	const kind = "race_check"
	f := mkFinding("issue_race", "e1", "high")

	// Each reconcile owns the transaction that scopes its advisory lock.
	reconcileTx := func(res checks.DetectResult) error {
		tx, err := pc.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := findings.Reconcile(ctx, pc.Queries.WithTx(tx), tenantID, asset.ID, kind, res); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	race := func(res checks.DetectResult) {
		t.Helper()
		const racers = 8
		var wg sync.WaitGroup
		errs := make([]error, racers)
		start := make(chan struct{})
		for i := range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = reconcileTx(res)
			}()
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatalf("concurrent reconcile: %v", err)
			}
		}
	}
	eventCounts := func() map[string]int {
		t.Helper()
		rows, err := pc.Pool.Query(ctx,
			`SELECT e.event, COUNT(*) FROM findings_events e
			 JOIN findings fi ON fi.id = e.finding_id
			 WHERE fi.asset_id=$1 AND fi.check_kind=$2 GROUP BY e.event`, asset.ID, kind)
		if err != nil {
			t.Fatalf("events: %v", err)
		}
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var event string
			var n int
			if err := rows.Scan(&event, &n); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out[event] = n
		}
		return out
	}

	race(checks.DetectResult{Found: []checks.Finding{f}})
	if got := eventCounts(); got["opened"] != 1 || len(got) != 1 {
		t.Fatalf("concurrent open emitted %v, want exactly one 'opened'", got)
	}

	race(checks.DetectResult{})
	if got := eventCounts(); got["resolved"] != 1 {
		t.Fatalf("concurrent resolve emitted %v, want exactly one 'resolved'", got)
	}

	race(checks.DetectResult{Found: []checks.Finding{f}})
	if got := eventCounts(); got["reopened"] != 1 {
		t.Fatalf("concurrent reopen emitted %v, want exactly one 'reopened'", got)
	}
}
