package assessor

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/danielmichaels/gecko/internal/checks"
	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/findings"
	"github.com/danielmichaels/gecko/internal/observer"

	"github.com/danielmichaels/gecko/internal/store"
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

// createFinding upserts an email-security finding and, when running under a real
// scan, emits a created/updated observation for it. entity_type, entity_key, and
// payload are derived from the finding params.
func (a *Assessor) createFinding(
	ctx context.Context,
	params interface{},
	logMessage string,
	issueType string,
) error {
	var (
		err        error
		entityType string
		entityKey  string
		payload    []byte
	)
	switch p := params.(type) {
	case store.AssessCreateSPFFindingParams:
		_, err = a.store.AssessCreateSPFFinding(ctx, p)
		entityType, entityKey = observer.EntitySPFFinding, p.IssueType
		payload = observer.PayloadJSON(map[string]any{
			"issue_type": p.IssueType, "severity": string(p.Severity),
			"status": string(p.Status), "value": p.SpfValue.String, "details": p.Details.String,
		})
	case store.AssessCreateDKIMFindingParams:
		_, err = a.store.AssessCreateDKIMFinding(ctx, p)
		entityType = observer.EntityDKIMFinding
		entityKey = p.IssueType + "|" + p.Selector.String
		payload = observer.PayloadJSON(map[string]any{
			"issue_type": p.IssueType, "selector": p.Selector.String, "severity": string(p.Severity),
			"status": string(p.Status), "value": p.DkimValue.String, "details": p.Details.String,
		})
	case store.AssessCreateDKIMFindingNoSelectorParams:
		_, err = a.store.AssessCreateDKIMFindingNoSelector(ctx, p)
		entityType, entityKey = observer.EntityDKIMFinding, p.IssueType
		payload = observer.PayloadJSON(map[string]any{
			"issue_type": p.IssueType, "severity": string(p.Severity),
			"status": string(p.Status), "value": p.DkimValue.String, "details": p.Details.String,
		})
	case store.AssessCreateDMARCFindingParams:
		_, err = a.store.AssessCreateDMARCFinding(ctx, p)
		entityType, entityKey = observer.EntityDMARCFinding, p.IssueType
		payload = observer.PayloadJSON(map[string]any{
			"issue_type": p.IssueType, "severity": string(p.Severity), "status": string(p.Status),
			"policy": p.Policy.String, "value": p.DmarcValue.String, "details": p.Details.String,
		})
	default:
		return fmt.Errorf("unsupported finding type")
	}
	if err != nil {
		a.logger.WarnContext(ctx, logMessage, "error", err)
		return fmt.Errorf("create finding: %s %w", issueType, err)
	}

	if oErr := observer.New(a.store).RecordFindingChange(ctx, a.identity, entityType, entityKey, payload); oErr != nil {
		a.logger.WarnContext(ctx, "failed to emit finding observation",
			"entity_type", entityType, "entity_key", entityKey, "error", oErr)
	}
	return nil
}
