// Package observer records observed DNS facts into the append-only observation
// log while keeping the live projection tables in sync. It is the write side of
// the middle-path "observation log" model: live tables remain the cheap
// current-state projection, and domain_observations is the product-facing change
// timeline.
package observer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Change types stored in domain_observations.change_type.
const (
	ChangeCreated = "created"
	ChangeUpdated = "updated"
	ChangeDeleted = "deleted"
)

// Entity types stored in domain_observations.entity_type.
const (
	EntityARecord      = "a_record"
	EntityAAAARecord   = "aaaa_record"
	EntityCNAMERecord  = "cname_record"
	EntityMXRecord     = "mx_record"
	EntityTXTRecord    = "txt_record"
	EntityNSRecord     = "ns_record"
	EntitySOARecord    = "soa_record"
	EntityPTRRecord    = "ptr_record"
	EntityCAARecord    = "caa_record"
	EntitySRVRecord    = "srv_record"
	EntityDNSKEYRecord = "dnskey_record"
	EntityDSRecord     = "ds_record"
	EntityRRSIGRecord  = "rrsig_record"

	EntityZoneTransferAttempt = "zone_transfer_attempt"
	EntitySPFFinding          = "spf_finding"
	EntityDKIMFinding         = "dkim_finding"
	EntityDMARCFinding        = "dmarc_finding"
	EntityZoneTransferFinding = "zone_transfer_finding"
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

// Recordable reports whether the identity is populated enough to stamp an
// observation. The assessor/scanner only set it when running under a real scan,
// so unit tests that exercise finding logic without a scan skip emission.
func (id DomainIdentity) Recordable() bool {
	return id.TenantID != 0 && id.DomainID != 0
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

// observedEntity is one record seen in the current scan: its canonical payload
// and a closure that upserts it into the projection.
type observedEntity struct {
	upsert  func(context.Context) error
	payload []byte
}

// currentEntity is one record already in the projection: its canonical payload
// and a closure that deletes it.
type currentEntity struct {
	delete  func(context.Context) error
	payload []byte
}

// sync is the generic per-type engine. It upserts every observed entity (so the
// projection reflects current truth), then emits created/updated observations and
// — only when authoritative — deletes projection rows absent from the observed
// set, emitting a matching deleted observation. The caller supplies the observed
// and current entities keyed by each type's natural key; payloads are compared to
// distinguish updated from unchanged.
func (r *Recorder) sync(
	ctx context.Context,
	ident DomainIdentity,
	entityType string,
	observed map[string]observedEntity,
	current map[string]currentEntity,
	authoritative bool,
) error {
	obsPayloads := make(map[string]string, len(observed))
	for k, e := range observed {
		obsPayloads[k] = string(e.payload)
	}
	curPayloads := make(map[string]string, len(current))
	for k, e := range current {
		curPayloads[k] = string(e.payload)
	}

	// Upsert every observed entity (created, updated, and unchanged) so the
	// projection — and its updated_at — reflect the current scan.
	for k := range observed {
		if err := observed[k].upsert(ctx); err != nil {
			return fmt.Errorf("upsert %s %q: %w", entityType, k, err)
		}
	}

	created, updated, deleted := planSync(obsPayloads, curPayloads, authoritative)
	for _, k := range created {
		if err := r.emit(ctx, ident, entityType, k, ChangeCreated, observed[k].payload); err != nil {
			return err
		}
	}
	for _, k := range updated {
		if err := r.emit(ctx, ident, entityType, k, ChangeUpdated, observed[k].payload); err != nil {
			return err
		}
	}
	for _, k := range deleted {
		if err := current[k].delete(ctx); err != nil {
			return fmt.Errorf("delete %s %q: %w", entityType, k, err)
		}
		if err := r.emit(ctx, ident, entityType, k, ChangeDeleted, current[k].payload); err != nil {
			return err
		}
	}
	return nil
}

// RecordFindingChange appends one observation for a finding/attempt that the
// caller has already upserted into its projection — but only when the payload
// differs from the most-recent prior observation for the same entity. An
// unchanged re-observation emits nothing, matching the DNS-record path's
// suppress-unchanged behavior and keeping the append-only log free of per-scan
// noise. change_type is 'created' on first sighting, 'updated' on a real change.
// Unlike the DNS-record recorders this does not sync deletions — findings and
// attempts are upsert-only (never deleted by the assessor/scanner).
//
// It is a no-op when the identity is not Recordable (the assessor/scanner run
// without a scan in unit tests), so callers need not guard the call themselves.
func (r *Recorder) RecordFindingChange(
	ctx context.Context,
	ident DomainIdentity,
	entityType, entityKey string,
	payload []byte,
) error {
	if !ident.Recordable() {
		return nil
	}
	_, err := r.q.ObservationsCreateIfChanged(ctx, store.ObservationsCreateIfChangedParams{
		TenantID:   ident.TenantID,
		DomainName: ident.DomainName,
		EntityType: entityType,
		EntityKey:  entityKey,
		DomainID:   pgtype.Int4{Int32: ident.DomainID, Valid: true},
		DomainUid:  ident.DomainUID,
		ScanID:     pgtype.Int8{Int64: ident.ScanID, Valid: ident.ScanID != 0},
		Payload:    payload,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // payload unchanged; suppressed
	}
	if err != nil {
		return fmt.Errorf("emit %s observation for %q: %w", entityType, entityKey, err)
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

// PayloadJSON marshals an observation payload map deterministically (encoding/json
// sorts map keys), so observed and current payloads built from the same fields
// compare byte-for-byte and updated detection is stable. It is the single marshal
// boundary shared by the DNS-record recorders and the finding/attempt emitters.
func PayloadJSON(m map[string]any) []byte {
	b, _ := json.Marshal(m)
	return b
}

// planSync compares observed vs current entities (keyed by their natural key,
// valued by a canonical payload string) and classifies each into created,
// updated (key in both but payload changed), or deleted. Deletions are gated on
// `authoritative` so an indeterminate resolution never deletes. Outputs sorted.
func planSync(
	observed, current map[string]string,
	authoritative bool,
) (created, updated, deleted []string) {
	for k, ov := range observed {
		cv, ok := current[k]
		switch {
		case !ok:
			created = append(created, k)
		case ov != cv:
			updated = append(updated, k)
		}
	}
	if authoritative {
		for k := range current {
			if _, ok := observed[k]; !ok {
				deleted = append(deleted, k)
			}
		}
	}
	sort.Strings(created)
	sort.Strings(updated)
	sort.Strings(deleted)
	return created, updated, deleted
}
