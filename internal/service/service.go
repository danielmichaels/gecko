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

// Service holds the shared dependencies used across all domain service methods.
type Service struct {
	Conf         *config.Conf
	Log          *slog.Logger
	DB           *store.Queries
	Pool         *pgxpool.Pool
	AuthProvider auth.Provider
	scheduler    DomainScanScheduler
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
	return &Service{
		Conf:         conf,
		Log:          log,
		DB:           db,
		Pool:         pool,
		AuthProvider: authProvider,
		scheduler:    &riverScheduler{rc: rc, conf: conf},
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

// AuthService returns the Auth sub-service.
func (s *Service) AuthService() *AuthService {
	return &AuthService{s}
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
