package findings_test

import (
	"context"
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
		if err := findings.Reconcile(ctx, pc.Queries, tenantID, assetID, checkKind, finds); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}
	// getFinding returns (id, status, resolved) or fails if absent.
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

	// 1. Both open on first sight.
	reconcile(a, b)
	aID, aStatus, _ := getFinding("issue_a", "")
	bID, bStatus, _ := getFinding("issue_b", "sel1")
	if aStatus != "open" || bStatus != "open" {
		t.Fatalf("statuses = %s/%s, want open/open", aStatus, bStatus)
	}
	if got := events(aID); len(got) != 1 || got[0] != "opened" {
		t.Fatalf("a events = %v, want [opened]", got)
	}

	// 2. KEY STABILITY: re-reconciling identical output must not churn -- same ids,
	// still open, no new events.
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

	// 3. b becomes absent -> resolved; a stays open.
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

	// 4. b returns -> reopened as the SAME row (id preserved), resolved_at cleared.
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

	// 5. empty output resolves everything for the scope.
	reconcile()
	if _, aStatus, _ := getFinding("issue_a", ""); aStatus != "resolved" {
		t.Fatalf("a status = %s, want resolved", aStatus)
	}
	if _, bStatus, _ := getFinding("issue_b", "sel1"); bStatus != "resolved" {
		t.Fatalf("b status = %s, want resolved", bStatus)
	}
}

// TestReconcileScopeIsolation confirms one check's reconcile never resolves another
// check's findings on the same asset.
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
	if err := findings.Reconcile(ctx, pc.Queries, tenantID, asset.ID, "check_one", []checks.Finding{f}); err != nil {
		t.Fatal(err)
	}
	// Reconcile a DIFFERENT check with empty output; check_one's finding must survive.
	if err := findings.Reconcile(ctx, pc.Queries, tenantID, asset.ID, "check_two", nil); err != nil {
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
