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

type DomainScanScheduler interface {
	Schedule(
		ctx context.Context,
		tx pgx.Tx,
		st *store.Queries,
		target jobs.DomainScanTarget,
		source store.DomainSource,
	) (int64, error)
}

type TenantStatsRefresher interface {
	RefreshTenantStats(ctx context.Context, tenantID int32) error
}

type EmailEnqueuer interface {
	EnqueueEmail(ctx context.Context, tx pgx.Tx, msg mailer.Message) error
}

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

func (s *Service) DomainsService() *DomainsService {
	return &DomainsService{s}
}

func (s *Service) RecordsService() *RecordsService {
	return &RecordsService{s}
}

func (s *Service) FindingsService() *FindingsService {
	return &FindingsService{s}
}

func (s *Service) AuthService() *AuthService {
	return &AuthService{s}
}

func (s *Service) ScansService() *ScansService {
	return &ScansService{s}
}

func (s *Service) UsersService() *UsersService {
	return &UsersService{s}
}

func (s *Service) InvitationsService() *InvitationsService {
	return &InvitationsService{s}
}

func (s *Service) APIKeysService() *APIKeysService {
	return &APIKeysService{s}
}

func (s *Service) SettingsService() *SettingsService {
	return &SettingsService{s}
}

func (s *Service) NotificationsService() *NotificationsService {
	return &NotificationsService{s}
}

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
		Source:              store.ScanSource(source),
		Force:               true,
		RecencyWindow:       r.conf.AppConf.ScanRecencyWindow,
		Concurrency:         r.conf.AppConf.EnumerationConcurrencyLimit,
	})
}

func (r *riverScheduler) RefreshTenantStats(ctx context.Context, tenantID int32) error {
	_, err := r.rc.Insert(ctx, jobs.RefreshTenantStatsArgs{TenantID: tenantID}, nil)
	return err
}

func (r *riverScheduler) EnqueueEmail(ctx context.Context, tx pgx.Tx, msg mailer.Message) error {
	_, err := r.rc.InsertTx(ctx, tx, jobs.SendEmailArgs{
		To:      msg.To,
		Subject: msg.Subject,
		HTML:    msg.HTML,
		Text:    msg.Text,
	}, nil)
	return err
}
