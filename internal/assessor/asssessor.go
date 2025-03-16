package assessor

import (
	"context"
	"fmt"
	"github.com/danielmichaels/gecko/internal/dnsclient"
	"log/slog"
	"os"

	"github.com/danielmichaels/gecko/internal/store"
)

type Config struct {
	Logger    *slog.Logger
	Store     *store.Queries
	DNSClient *dnsclient.DNSClient
}

type Assessor struct {
	logger    *slog.Logger
	store     *store.Queries
	dnsClient *dnsclient.DNSClient
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
	}
}

func (a *Assessor) createFinding(
	ctx context.Context,
	params interface{},
	logMessage string,
	issueType string,
) error {
	var err error
	switch p := params.(type) {
	case store.AssessCreateSPFFindingParams:
		err = a.store.AssessCreateSPFFinding(ctx, p)
	case store.AssessCreateDKIMFindingParams:
		err = a.store.AssessCreateDKIMFinding(ctx, p)
	case store.AssessCreateDKIMFindingNoSelectorParams:
		err = a.store.AssessCreateDKIMFindingNoSelector(ctx, p)
	case store.AssessCreateDMARCFindingParams:
		err = a.store.AssessCreateDMARCFinding(ctx, p)
	default:
		return fmt.Errorf("unsupported finding type")
	}
	if err != nil {
		a.logger.WarnContext(ctx, logMessage, "error", err)
		return fmt.Errorf("create finding: %s %w", issueType, err)
	}
	return nil
}
