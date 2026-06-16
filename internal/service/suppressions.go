package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// SuppressionsService manages finding suppressions: silence rules (mute a check
// by kind+issue_type, tenant-global or per-domain) and per-finding acks. Both are
// applied at read time by the findings queries; nothing here touches the assessor
// finding tables, so suppressions persist across re-scans.
type SuppressionsService struct {
	*Service
}

// validFindingKinds is the canonical kind set shared by every finding read
// surface (matches the literals in FindingsListByTenant / FindingResolveByUID).
// A silence rule's kind must be one of these.
var validFindingKinds = map[string]bool{
	"SPF": true, "DKIM": true, "DMARC": true, "ZONE": true, "CERT": true,
	"DNSSEC": true, "DANGLING": true, "CNAME": true, "CAA_CONFIG": true,
	"CAA_COMPLIANCE": true, "MIN_RECORDS": true, "EMAIL_COMPLIANCE": true,
	"NS_CONFIG": true, "NS_REDUNDANCY": true, "NS_REACHABILITY": true,
	"NS_LATENCY": true, "NS_CONSISTENCY": true,
}

// knownIssueType reports whether issueType is a check code the assessors emit.
// findingTitles (findings.go) is the catalog of every issue type plus the two
// synthesized zone/dangling outcomes, so it doubles as the allowlist.
func knownIssueType(issueType string) bool {
	switch issueType {
	case "zone_transfer_exposed", "zone_transfer_refused",
		"subdomain_takeover", "dangling_cname",
		"high_latency", "resolver_mismatch":
		return true
	}
	_, ok := findingTitles[issueType]
	return ok
}

// SuppressionView is a presentation-ready suppression for the management screen.
type SuppressionView struct {
	UID        string
	Scope      string // "tenant" | "domain" | "finding"
	State      string // silenced | acknowledged | resolved
	Kind       string
	IssueType  string
	FindingUID string
	DomainUID  string
	DomainName string
	Reason     string
	CreatedBy  string // email, may be empty
	CreatedAt  string // "2006-01-02"
	ExpiresAt  string // "2006-01-02", empty = never
}

// CreateSilenceRule mutes a check (kind+issue_type). When domainUID is nil the
// rule is tenant-global (applies to every domain); when set it scopes to that one
// domain. Idempotent: re-silencing the same check refreshes the reason/expiry.
// Owner/manager only.
func (s *SuppressionsService) CreateSilenceRule(
	ctx context.Context,
	p *auth.Principal,
	kind, issueType string,
	domainUID *string,
	reason string,
	expiresAt *time.Time,
) (store.FindingSuppressions, error) {
	if err := ownerOrManager(p); err != nil {
		return store.FindingSuppressions{}, err
	}
	if !validFindingKinds[kind] || !knownIssueType(issueType) {
		return store.FindingSuppressions{}, msgErr(ErrInvalidInput, "unknown check kind or issue type")
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return store.FindingSuppressions{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	var (
		row   store.FindingSuppressions
		ident observer.DomainIdentity
		scope = "tenant"
	)
	if domainUID != nil {
		dom, derr := st.DomainsGetByID(ctx, store.DomainsGetByIDParams{
			Uid:      *domainUID,
			TenantID: pgtype.Int4{Int32: p.TenantID, Valid: true},
		})
		if derr != nil {
			if errors.Is(derr, pgx.ErrNoRows) {
				return store.FindingSuppressions{}, ErrNotFound
			}
			return store.FindingSuppressions{}, fmt.Errorf("resolve domain: %w", derr)
		}
		row, err = st.SuppressionsUpsertDomainRule(ctx, store.SuppressionsUpsertDomainRuleParams{
			TenantID:  p.TenantID,
			DomainID:  pgtype.Int4{Int32: dom.ID, Valid: true},
			Kind:      pgtype.Text{String: kind, Valid: true},
			IssueType: pgtype.Text{String: issueType, Valid: true},
			State:     store.SuppressionStateSilenced,
			Reason:    optText(reason),
			CreatedBy: pgtype.Int4{Int32: p.UserID, Valid: true},
			ExpiresAt: optTime(expiresAt),
		})
		scope = "domain"
		ident = observer.DomainIdentity{
			DomainUID: dom.Uid, DomainName: dom.Name, TenantID: p.TenantID, DomainID: dom.ID,
		}
	} else {
		row, err = st.SuppressionsUpsertGlobalRule(ctx, store.SuppressionsUpsertGlobalRuleParams{
			TenantID:  p.TenantID,
			Kind:      pgtype.Text{String: kind, Valid: true},
			IssueType: pgtype.Text{String: issueType, Valid: true},
			State:     store.SuppressionStateSilenced,
			Reason:    optText(reason),
			CreatedBy: pgtype.Int4{Int32: p.UserID, Valid: true},
			ExpiresAt: optTime(expiresAt),
		})
	}
	if err != nil {
		return store.FindingSuppressions{}, fmt.Errorf("upsert silence rule: %w", err)
	}

	if oErr := s.emitSuppression(ctx, st, ident, row, scope, "silenced"); oErr != nil {
		return store.FindingSuppressions{}, oErr
	}
	if err := tx.Commit(ctx); err != nil {
		return store.FindingSuppressions{}, fmt.Errorf("commit: %w", err)
	}
	s.refreshStats(ctx, p.TenantID)
	return row, nil
}

// AcknowledgeFinding marks one finding instance (by its stable uid) as handled.
// state must be 'acknowledged' or 'resolved'. The finding is resolved to its
// domain (tenant-gated) so a cross-tenant uid guess yields ErrNotFound.
func (s *SuppressionsService) AcknowledgeFinding(
	ctx context.Context,
	p *auth.Principal,
	findingUID string,
	state store.SuppressionState,
	reason string,
	expiresAt *time.Time,
) (store.FindingSuppressions, error) {
	if err := ownerOrManager(p); err != nil {
		return store.FindingSuppressions{}, err
	}
	if state != store.SuppressionStateAcknowledged && state != store.SuppressionStateResolved {
		return store.FindingSuppressions{}, msgErr(ErrInvalidInput, "state must be acknowledged or resolved")
	}

	target, err := s.DB.FindingResolveByUID(ctx, store.FindingResolveByUIDParams{
		TenantID:  pgtype.Int4{Int32: p.TenantID, Valid: true},
		TargetUid: findingUID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return store.FindingSuppressions{}, ErrNotFound
		}
		return store.FindingSuppressions{}, fmt.Errorf("resolve finding: %w", err)
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return store.FindingSuppressions{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	row, err := st.SuppressionsUpsertAck(ctx, store.SuppressionsUpsertAckParams{
		TenantID:   p.TenantID,
		DomainID:   pgtype.Int4{Int32: target.DomainID, Valid: true},
		FindingUid: pgtype.Text{String: findingUID, Valid: true},
		State:      state,
		Reason:     optText(reason),
		CreatedBy:  pgtype.Int4{Int32: p.UserID, Valid: true},
		ExpiresAt:  optTime(expiresAt),
	})
	if err != nil {
		return store.FindingSuppressions{}, fmt.Errorf("upsert ack: %w", err)
	}

	ident := observer.DomainIdentity{
		DomainUID: target.DomainUid, DomainName: target.DomainName,
		TenantID: p.TenantID, DomainID: target.DomainID,
	}
	if oErr := s.emitSuppression(ctx, st, ident, row, "finding", string(state)); oErr != nil {
		return store.FindingSuppressions{}, oErr
	}
	if err := tx.Commit(ctx); err != nil {
		return store.FindingSuppressions{}, fmt.Errorf("commit: %w", err)
	}
	s.refreshStats(ctx, p.TenantID)
	return row, nil
}

// DeleteSuppression removes a rule or ack by its uid (tenant-scoped). Owner/manager only.
func (s *SuppressionsService) DeleteSuppression(
	ctx context.Context,
	p *auth.Principal,
	uid string,
) error {
	if err := ownerOrManager(p); err != nil {
		return err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	row, err := st.SuppressionsDeleteByUID(ctx, store.SuppressionsDeleteByUIDParams{
		Uid:      uid,
		TenantID: p.TenantID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("delete suppression: %w", err)
	}

	ident := s.identForRow(ctx, st, row)
	if oErr := s.emitSuppression(ctx, st, ident, row, scopeOfRow(row), "removed"); oErr != nil {
		return oErr
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	s.refreshStats(ctx, p.TenantID)
	return nil
}

// UnacknowledgeFinding removes the ack for a finding, tenant-scoped.
func (s *SuppressionsService) UnacknowledgeFinding(
	ctx context.Context,
	p *auth.Principal,
	findingUID string,
) error {
	if err := ownerOrManager(p); err != nil {
		return err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := s.DB.WithTx(tx)

	row, err := st.SuppressionsDeleteAckByFindingUID(ctx, store.SuppressionsDeleteAckByFindingUIDParams{
		FindingUid: pgtype.Text{String: findingUID, Valid: true},
		TenantID:   p.TenantID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("delete ack: %w", err)
	}

	ident := s.identForRow(ctx, st, row)
	if oErr := s.emitSuppression(ctx, st, ident, row, "finding", "removed"); oErr != nil {
		return oErr
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	s.refreshStats(ctx, p.TenantID)
	return nil
}

// ListSuppressions returns every rule and ack for the tenant for the management
// view. Read-only, so any authenticated role may call it.
func (s *SuppressionsService) ListSuppressions(
	ctx context.Context,
	p *auth.Principal,
) ([]SuppressionView, error) {
	rows, err := s.DB.SuppressionsListByTenant(ctx, p.TenantID)
	if err != nil {
		return nil, fmt.Errorf("list suppressions: %w", err)
	}
	out := make([]SuppressionView, 0, len(rows))
	for _, r := range rows {
		out = append(out, SuppressionView{
			UID:        r.Uid,
			Scope:      scopeOf(r.FindingUid.Valid, r.DomainID.Valid),
			State:      string(r.State),
			Kind:       r.Kind.String,
			IssueType:  r.IssueType.String,
			FindingUID: r.FindingUid.String,
			DomainUID:  r.DomainUid.String,
			DomainName: r.DomainName.String,
			Reason:     r.Reason.String,
			CreatedBy:  r.CreatedByEmail.String,
			CreatedAt:  fmtDate(r.CreatedAt),
			ExpiresAt:  fmtDate(r.ExpiresAt),
		})
	}
	return out, nil
}

// emitSuppression stamps a finding_suppression observation onto the timeline. A
// zero identity (tenant-global rule) is skipped by Recordable() — acceptable, as
// a tenant-wide rule has no single domain to attach to.
func (s *SuppressionsService) emitSuppression(
	ctx context.Context,
	st *store.Queries,
	ident observer.DomainIdentity,
	row store.FindingSuppressions,
	scope, action string,
) error {
	if !ident.Recordable() {
		return nil
	}
	payload := observer.PayloadJSON(map[string]any{
		"scope":       scope,
		"action":      action,
		"state":       string(row.State),
		"kind":        row.Kind.String,
		"issue_type":  row.IssueType.String,
		"finding_uid": row.FindingUid.String,
		"reason":      row.Reason.String,
	})
	if err := observer.New(st).RecordFindingChange(
		ctx, ident, observer.EntityFindingSuppression, row.Uid, payload,
	); err != nil {
		return fmt.Errorf("emit suppression observation: %w", err)
	}
	return nil
}

// identForRow rebuilds a domain identity for an observation from a suppression
// row's domain_id. Returns a zero identity (emission skipped) for tenant-global rules.
func (s *SuppressionsService) identForRow(
	ctx context.Context,
	st *store.Queries,
	row store.FindingSuppressions,
) observer.DomainIdentity {
	if !row.DomainID.Valid {
		return observer.DomainIdentity{}
	}
	dom, err := st.DomainsGetByDomainID(ctx, row.DomainID.Int32)
	if err != nil {
		return observer.DomainIdentity{}
	}
	return observer.DomainIdentity{
		DomainUID: dom.Uid, DomainName: dom.Name, TenantID: row.TenantID, DomainID: dom.ID,
	}
}

func (s *SuppressionsService) refreshStats(ctx context.Context, tenantID int32) {
	if s.statsRefresher == nil {
		return
	}
	if err := s.statsRefresher.RefreshTenantStats(ctx, tenantID); err != nil {
		s.Log.WarnContext(ctx, "enqueue tenant stats refresh", "error", err)
	}
}

// scopeOf derives the management-view scope label from a row's shape.
func scopeOf(hasFindingUID, hasDomain bool) string {
	switch {
	case hasFindingUID:
		return "finding"
	case hasDomain:
		return "domain"
	default:
		return "tenant"
	}
}

func scopeOfRow(row store.FindingSuppressions) string {
	return scopeOf(row.FindingUid.Valid, row.DomainID.Valid)
}

func optText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

func optTime(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func fmtDate(ts pgtype.Timestamptz) string {
	if !ts.Valid {
		return ""
	}
	return ts.Time.Format("2006-01-02")
}
