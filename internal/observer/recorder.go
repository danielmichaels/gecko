// Package observer records observed DNS facts into the append-only observation
// log while keeping the live projection tables in sync. It is the write side of
// the middle-path "observation log" model: live tables remain the cheap
// current-state projection, and domain_observations is the product-facing change
// timeline.
package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// DomainIdentity is the stable identity stamped onto every observation. It is
// defined here (rather than reusing jobs.DomainJobArgs) so the observer package
// does not import jobs — jobs imports observer, and the reverse would cycle.
type DomainIdentity struct {
	DomainUID  string
	DomainName string
	TenantID   int32
	DomainID   int32
	ScanID     int64
}

// Recorder writes observed DNS facts into the live projection and the
// observation log. Its store handle must be transaction-scoped so a projection
// upsert/delete and its matching observation share one atomic boundary.
type Recorder struct {
	q *store.Queries
}

// New returns a Recorder over a (transaction-scoped) store handle.
func New(q *store.Queries) *Recorder {
	return &Recorder{q: q}
}

// RecordA syncs the observed A records for a domain: it upserts every observed
// IP into the projection, emits a "created" observation for each genuinely new
// IP, and — only when the resolution was authoritative — deletes projection rows
// whose IPs were not observed and emits a matching "deleted" observation.
func (r *Recorder) RecordA(
	ctx context.Context,
	ident DomainIdentity,
	observedIPs []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}

	currentRows, err := r.q.RecordsGetAByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load current A records: %w", err)
	}
	current := make([]string, len(currentRows))
	for i, row := range currentRows {
		current[i] = row.Ipv4Address
	}

	// Upsert every observed IP so the projection reflects current truth. The
	// upsert is idempotent; observations distinguish genuinely-new from unchanged.
	for _, ip := range observedIPs {
		if _, err := r.q.RecordsCreateA(ctx, store.RecordsCreateAParams{
			DomainID:    domainID,
			Ipv4Address: ip,
		}); err != nil {
			return fmt.Errorf("upsert A record %q: %w", ip, err)
		}
	}

	created, deleted := planChanges(observedIPs, current, authoritative)

	for _, ip := range created {
		if err := r.emit(ctx, ident, EntityARecord, ip, ChangeCreated, aPayload(ip)); err != nil {
			return err
		}
	}
	for _, ip := range deleted {
		if err := r.q.RecordsDeleteA(ctx, store.RecordsDeleteAParams{
			DomainID:    domainID,
			Ipv4Address: ip,
		}); err != nil {
			return fmt.Errorf("delete A record %q: %w", ip, err)
		}
		if err := r.emit(ctx, ident, EntityARecord, ip, ChangeDeleted, aPayload(ip)); err != nil {
			return err
		}
	}
	return nil
}

// emit appends one row to the observation log, stamping the denormalized domain
// identity so the timeline survives a domain delete/re-add.
func (r *Recorder) emit(
	ctx context.Context,
	ident DomainIdentity,
	entityType, entityKey, changeType string,
	payload []byte,
) error {
	_, err := r.q.ObservationsCreate(ctx, store.ObservationsCreateParams{
		TenantID:   ident.TenantID,
		DomainID:   pgtype.Int4{Int32: ident.DomainID, Valid: true},
		DomainUid:  ident.DomainUID,
		DomainName: ident.DomainName,
		ScanID:     pgtype.Int8{Int64: ident.ScanID, Valid: ident.ScanID != 0},
		EntityType: entityType,
		EntityKey:  entityKey,
		ChangeType: changeType,
		Payload:    payload,
	})
	if err != nil {
		return fmt.Errorf("emit %s observation for %q: %w", changeType, entityKey, err)
	}
	return nil
}

func aPayload(ip string) []byte {
	b, _ := json.Marshal(map[string]string{"ipv4_address": ip})
	return b
}

// Change types stored in domain_observations.change_type.
const (
	ChangeCreated = "created"
	ChangeUpdated = "updated"
	ChangeDeleted = "deleted"
)

// Entity types stored in domain_observations.entity_type.
const (
	EntityARecord = "a_record"
)

// planChanges compares the authoritatively observed key set against the current
// projection key set and returns the keys to create and to delete. Deletions are
// only proposed when `authoritative` is true: an indeterminate resolution
// (SERVFAIL/timeout) yields an empty observed set with authoritative=false, and
// treating that as "everything was deleted" would emit phantom deletions.
//
// Keys present in both sets are unchanged and appear in neither return value.
// Outputs are sorted for deterministic observation ordering.
func planChanges(observed, current []string, authoritative bool) (created, deleted []string) {
	observedSet := make(map[string]struct{}, len(observed))
	for _, k := range observed {
		observedSet[k] = struct{}{}
	}
	currentSet := make(map[string]struct{}, len(current))
	for _, k := range current {
		currentSet[k] = struct{}{}
	}

	// Iterate the sets (not the input slices) so duplicate observed keys — which
	// DNS can legitimately return — collapse to one created entry.
	for k := range observedSet {
		if _, ok := currentSet[k]; !ok {
			created = append(created, k)
		}
	}
	if authoritative {
		for k := range currentSet {
			if _, ok := observedSet[k]; !ok {
				deleted = append(deleted, k)
			}
		}
	}
	sort.Strings(created)
	sort.Strings(deleted)
	return created, deleted
}
