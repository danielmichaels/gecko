// Package service holds the application business logic layer.
//
// Service methods follow the convention: the first argument is ctx, the second
// is p *auth.Principal (the authenticated caller), followed by any method-specific
// inputs. The Principal is passed explicitly rather than read from context so that
// the compiler enforces authentication at every call site.
// Exception: the identity-establishing methods (Login, Signup, AcceptInvite) are
// unauthenticated entry points and take no Principal.
package service

import (
	"context"
	"errors"
	"log/slog"

	"github.com/danielmichaels/gecko/internal/auth"
	"github.com/danielmichaels/gecko/internal/config"
	"github.com/danielmichaels/gecko/internal/jobs"
	"github.com/danielmichaels/gecko/internal/mailer"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
)

var (
	ErrNotFound        = errors.New("not found")
	ErrForbidden       = errors.New("forbidden")
	ErrConflict        = errors.New("conflict")
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrInvalidInput    = errors.New("invalid input")
)

// DomainScanScheduler schedules a domain scan job inside a transaction. The
// seam lets Create/Update tests run without a live River queue.
type DomainScanScheduler interface {
	Schedule(
		ctx context.Context,
		tx pgx.Tx,
		st *store.Queries,
		target jobs.DomainScanTarget,
		source store.DomainSource,
	) (int64, error)
}

// TenantStatsRefresher enqueues an out-of-band recompute of a single tenant's
// cached stat strip. The seam lets handlers trigger an immediate refresh (e.g.
// after a delete drops a tenant's counts) without coupling the service to a live
// River queue; a nil refresher just skips the enqueue and lets the periodic job
// catch up.
type TenantStatsRefresher interface {
	RefreshTenantStats(ctx context.Context, tenantID int32) error
}

// EmailEnqueuer queues an outbound email inside a transaction so the message and
// the row it depends on (e.g. a password-reset token) commit atomically. The seam
// lets auth flows enqueue mail without a live River queue in tests; a nil enqueuer
// skips the send (the row is still written).
type EmailEnqueuer interface {
	EnqueueEmail(ctx context.Context, tx pgx.Tx, msg mailer.Message) error
}

// Service holds the shared dependencies used across all domain service methods.
type Service struct {
	Conf           *config.Conf
	Log            *slog.Logger
	DB             *store.Queries
	Pool           *pgxpool.Pool
	AuthProvider   auth.Provider
	scheduler      DomainScanScheduler
	statsRefresher TenantStatsRefresher
	emailer        EmailEnqueuer
}

// New constructs a Service with all required dependencies wired. The production
// scan scheduler delegates to jobs.EnqueueDomainScan via riverScheduler.
func New(
	conf *config.Conf,
	log *slog.Logger,
	db *store.Queries,
	pool *pgxpool.Pool,
	rc *river.Client[pgx.Tx],
	authProvider auth.Provider,
) *Service {
	sched := &riverScheduler{rc: rc, conf: conf}
	return &Service{
		Conf:           conf,
		Log:            log,
		DB:             db,
		Pool:           pool,
		AuthProvider:   authProvider,
		scheduler:      sched,
		statsRefresher: sched,
		emailer:        sched,
	}
}

// NewWithScheduler constructs a Service with a custom scheduler — used in
// tests to inject a fake that records calls without a live River queue.
func NewWithScheduler(
	conf *config.Conf,
	log *slog.Logger,
	db *store.Queries,
	pool *pgxpool.Pool,
	scheduler DomainScanScheduler,
	authProvider ...auth.Provider,
) *Service {
	svc := &Service{
		Conf:      conf,
		Log:       log,
		DB:        db,
		Pool:      pool,
		scheduler: scheduler,
	}
	// A fake that also implements TenantStatsRefresher (the production scheduler
	// does) gets wired as the refresher too; otherwise the enqueue is skipped.
	if r, ok := scheduler.(TenantStatsRefresher); ok {
		svc.statsRefresher = r
	}
	if e, ok := scheduler.(EmailEnqueuer); ok {
		svc.emailer = e
	}
	if len(authProvider) > 0 {
		svc.AuthProvider = authProvider[0]
	}
	return svc
}

// DomainsService returns the Domains sub-service.
func (s *Service) DomainsService() *DomainsService {
	return &DomainsService{s}
}

// RecordsService returns the Records sub-service.
func (s *Service) RecordsService() *RecordsService {
	return &RecordsService{s}
}

// FindingsService returns the Findings sub-service.
func (s *Service) FindingsService() *FindingsService {
	return &FindingsService{s}
}

// AuthService returns the Auth sub-service.
func (s *Service) AuthService() *AuthService {
	return &AuthService{s}
}

// ScansService returns the Scans sub-service.
func (s *Service) ScansService() *ScansService {
	return &ScansService{s}
}

// UsersService returns the Users sub-service.
func (s *Service) UsersService() *UsersService {
	return &UsersService{s}
}

// InvitationsService returns the Invitations sub-service.
func (s *Service) InvitationsService() *InvitationsService {
	return &InvitationsService{s}
}

// APIKeysService returns the APIKeys sub-service.
func (s *Service) APIKeysService() *APIKeysService {
	return &APIKeysService{s}
}

// riverScheduler is the production DomainScanScheduler that delegates to
// jobs.EnqueueDomainScan with the same options the former scheduleUserDomainScan used.
type riverScheduler struct {
	rc   *river.Client[pgx.Tx]
	conf *config.Conf
}

func (r *riverScheduler) Schedule(
	ctx context.Context,
	tx pgx.Tx,
	st *store.Queries,
	target jobs.DomainScanTarget,
	source store.DomainSource,
) (int64, error) {
	return jobs.EnqueueDomainScan(ctx, r.rc, tx, st, target, jobs.DomainScanOptions{
		EnumerateSubdomains: true,
		Source:              source,
		Force:               true,
		RecencyWindow:       r.conf.AppConf.ScanRecencyWindow,
		Concurrency:         r.conf.AppConf.EnumerationConcurrencyLimit,
	})
}

// RefreshTenantStats enqueues a single-tenant stat-strip recompute. The job's
// InsertOpts make it unique by args, so concurrent enqueues for the same tenant
// coalesce into one pending refresh.
func (r *riverScheduler) RefreshTenantStats(ctx context.Context, tenantID int32) error {
	_, err := r.rc.Insert(ctx, jobs.RefreshTenantStatsArgs{TenantID: tenantID}, nil)
	return err
}

// EnqueueEmail inserts a send_email job in the caller's transaction so the email
// and the row it depends on commit together.
func (r *riverScheduler) EnqueueEmail(ctx context.Context, tx pgx.Tx, msg mailer.Message) error {
	_, err := r.rc.InsertTx(ctx, tx, jobs.SendEmailArgs{
		To:      msg.To,
		Subject: msg.Subject,
		HTML:    msg.HTML,
		Text:    msg.Text,
	}, nil)
	return err
}
