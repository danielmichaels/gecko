// Package findings persists Detector output with a desired-state reconciler: the
// single write path that replaces the ~17 bespoke typed-table writers plus
// RecordFindingChange. Detect declares the problems TRUE NOW for an asset+check;
// Reconcile makes the findings table match, opening/reopening present findings and
// resolving absent ones, and records every transition in findings_events.
package findings

import (
	"context"
	"fmt"

	"github.com/danielmichaels/gecko/internal/checks"
	"github.com/danielmichaels/gecko/internal/store"
)

const (
	statusResolved = "resolved"

	eventOpened   = "opened"
	eventResolved = "resolved"
	eventReopened = "reopened"
)

// keyOf is the in-memory identity for a finding within one (asset, check) scope.
// The NUL separator can't appear in an issue_type or entity_key, so it can't
// collide two distinct findings into one key.
func keyOf(issueType, entityKey string) string {
	return issueType + "\x00" + entityKey
}

// Reconcile diffs the Detect output for one asset+check against the stored open
// findings and makes them match. q MUST be transaction-scoped so the upserts,
// resolves, and event rows commit atomically. found is "problems true now"; an
// empty slice resolves every open finding for the scope.
func Reconcile(
	ctx context.Context,
	q *store.Queries,
	tenantID int32,
	assetID int64,
	checkKind string,
	found []checks.Finding,
) error {
	present := make(map[string]struct{}, len(found))
	for _, f := range found {
		present[keyOf(f.IssueType, f.EntityKey)] = struct{}{}

		row, err := q.FindingsUpsert(ctx, store.FindingsUpsertParams{
			TenantID:  tenantID,
			AssetID:   assetID,
			CheckKind: checkKind,
			IssueType: f.IssueType,
			EntityKey: f.EntityKey,
			Severity:  f.Severity,
			Title:     f.Title,
			Details:   f.Details,
			Evidence:  f.Evidence,
		})
		if err != nil {
			return fmt.Errorf("upsert finding %s/%s: %w", checkKind, f.IssueType, err)
		}

		// prior_status "" = newly opened; "resolved" = reopened; "open" = unchanged.
		switch row.PriorStatus {
		case "":
			if err := q.FindingsEventInsert(ctx, store.FindingsEventInsertParams{FindingID: row.ID, Event: eventOpened}); err != nil {
				return fmt.Errorf("emit opened event: %w", err)
			}
		case statusResolved:
			if err := q.FindingsEventInsert(ctx, store.FindingsEventInsertParams{FindingID: row.ID, Event: eventReopened}); err != nil {
				return fmt.Errorf("emit reopened event: %w", err)
			}
		}
	}

	open, err := q.FindingsListOpenByAssetCheck(ctx, store.FindingsListOpenByAssetCheckParams{
		AssetID:   assetID,
		CheckKind: checkKind,
	})
	if err != nil {
		return fmt.Errorf("list open findings %s: %w", checkKind, err)
	}
	for _, o := range open {
		if _, ok := present[keyOf(o.IssueType, o.EntityKey)]; ok {
			continue
		}
		if err := q.FindingsResolve(ctx, o.ID); err != nil {
			return fmt.Errorf("resolve finding %d: %w", o.ID, err)
		}
		if err := q.FindingsEventInsert(ctx, store.FindingsEventInsertParams{FindingID: o.ID, Event: eventResolved}); err != nil {
			return fmt.Errorf("emit resolved event: %w", err)
		}
	}
	return nil
}
