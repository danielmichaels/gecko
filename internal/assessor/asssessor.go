package assessor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/danielmichaels/gecko/internal/checks"
	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/findings"
	"github.com/danielmichaels/gecko/internal/observer"

	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// resolutionString maps the resolver's tri-state onto the detect package's string
// form, so collectors record it in evidence without leaking the dnsclient type and
// a failed lookup (Indeterminate) stays distinguishable from authoritative absence.
func resolutionString(s dnsclient.ResolutionStatus) string {
	switch s {
	case dnsclient.ResolutionData:
		return detect.ResolutionData
	case dnsclient.ResolutionEmpty:
		return detect.ResolutionEmpty
	default:
		return detect.ResolutionIndeterminate
	}
}

type Config struct {
	Logger    *slog.Logger
	Store     *store.Queries
	DNSClient dnsclient.Resolver
	// HTTPProber probes CNAME targets for the dangling/takeover assessor. Left nil
	// outside tests; NewAssessor supplies the default outbound prober.
	HTTPProber HTTPProber
	// NSProber probes authoritative nameservers directly for the nameserver-health
	// assessor. Left nil outside tests; NewAssessor defaults it to the DNSClient
	// when that client supports direct probing.
	NSProber NameserverProber
	// Identity is the scan identity used to stamp observations. Left zero in unit
	// tests (which exercise finding logic without a scan); emission is skipped then.
	Identity observer.DomainIdentity
}

type Assessor struct {
	logger    *slog.Logger
	store     *store.Queries
	dnsClient dnsclient.Resolver
	prober    HTTPProber
	nsProber  NameserverProber
	identity  observer.DomainIdentity
}

func NewAssessor(cfg Config) *Assessor {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	dnsClient := cfg.DNSClient
	if dnsClient == nil {
		dnsClient = dnsclient.New()
	}

	prober := cfg.HTTPProber
	if prober == nil {
		prober = newHTTPProber()
	}

	nsProber := cfg.NSProber
	if nsProber == nil {
		if p, ok := dnsClient.(NameserverProber); ok {
			nsProber = p
		}
	}

	return &Assessor{
		store:     cfg.Store,
		logger:    logger,
		dnsClient: dnsClient,
		prober:    prober,
		nsProber:  nsProber,
		identity:  cfg.Identity,
	}
}

// getDomain loads a domain by its UID within the assessor's tenant, mapping a
// missing row to a caller-friendly not-found error.
func (a *Assessor) getDomain(
	ctx context.Context,
	domainUID string,
) (store.DomainsGetByIdentifierRow, error) {
	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		Uid:      domainUID,
		TenantID: pgtype.Int4{Int32: a.identity.TenantID, Valid: true},
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.DomainsGetByIdentifierRow{}, fmt.Errorf(
				"domain %s not found in database",
				domainUID,
			)
		}
		a.logger.ErrorContext(ctx, "Error looking up domain", "domain", domainUID, "error", err)
		return store.DomainsGetByIdentifierRow{}, err
	}
	return domain, nil
}

// reconcile resolves the domain's asset and persists the detector output via the
// desired-state reconciler. It is a no-op without a real scan identity (unit tests
// exercise detectors directly), so callers need not guard it. The reconcile runs
// on the pool store; it is idempotent and self-heals a partial run on the next
// scan (tx-wrapping is a Phase 2 follow-up).
func (a *Assessor) reconcile(
	ctx context.Context,
	domainName, checkKind string,
	found []checks.Finding,
) error {
	if a.identity.TenantID == 0 {
		return nil
	}
	asset, err := a.store.AssetsUpsertDomain(ctx, store.AssetsUpsertDomainParams{
		TenantID: a.identity.TenantID,
		Value:    domainName,
		Source:   "discovered",
	})
	if err != nil {
		return fmt.Errorf("resolve asset for %s: %w", domainName, err)
	}
	return findings.Reconcile(ctx, a.store, a.identity.TenantID, asset.ID, checkKind, found)
}
