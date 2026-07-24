// Package findings reconciles detector output with persisted finding state.
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

// keyOf joins fields with a separator neither field can contain.
func keyOf(issueType, entityKey string) string {
	return issueType + "\x00" + entityKey
}

// Reconcile atomically applies detector output within one asset/check scope.
// Found keys open, Indeterminate keys remain unchanged, and absent keys resolve.
// q must be transaction-scoped; the scope lock serializes concurrent updates.
func Reconcile(
	ctx context.Context,
	q *store.Queries,
	tenantID int32,
	assetID int64,
	checkKind string,
	res checks.DetectResult,
) error {
	if err := q.FindingsLockScope(ctx, store.FindingsLockScopeParams{
		AssetID:   assetID,
		CheckKind: checkKind,
	}); err != nil {
		return fmt.Errorf("lock scope %s: %w", checkKind, err)
	}

	present := make(map[string]struct{}, len(res.Found))
	for _, f := range res.Found {
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

	protected := make(map[string]struct{}, len(res.Indeterminate))
	for _, k := range res.Indeterminate {
		protected[keyOf(k.IssueType, k.EntityKey)] = struct{}{}
	}

	open, err := q.FindingsListOpenByAssetCheck(ctx, store.FindingsListOpenByAssetCheckParams{
		AssetID:   assetID,
		CheckKind: checkKind,
	})
	if err != nil {
		return fmt.Errorf("list open findings %s: %w", checkKind, err)
	}
	for _, o := range open {
		key := keyOf(o.IssueType, o.EntityKey)
		if _, ok := present[key]; ok {
			continue
		}
		if _, ok := protected[key]; ok {
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
