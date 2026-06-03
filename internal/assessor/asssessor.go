package assessor

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/observer"

	"github.com/danielmichaels/gecko/internal/store"
)

type Config struct {
	Logger    *slog.Logger
	Store     *store.Queries
	DNSClient *dnsclient.DNSClient
	// Identity is the scan identity used to stamp observations. Left zero in unit
	// tests (which exercise finding logic without a scan); emission is skipped then.
	Identity observer.DomainIdentity
}

type Assessor struct {
	logger    *slog.Logger
	store     *store.Queries
	dnsClient *dnsclient.DNSClient
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

	return &Assessor{
		store:     cfg.Store,
		logger:    logger,
		dnsClient: dnsClient,
		identity:  cfg.Identity,
	}
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
