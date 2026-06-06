// Package service holds the application business logic layer.
//
// Service methods follow the convention: the first argument is ctx, the second
// is p *auth.Principal (the authenticated caller), followed by any method-specific
// inputs. The Principal is passed explicitly rather than read from context so that
// the compiler enforces authentication at every call site.
package service

import (
	"errors"
	"log/slog"

	"github.com/danielmichaels/gecko/internal/config"
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
)

// Service holds the shared dependencies used across all domain service methods.
type Service struct {
	Conf *config.Conf
	Log  *slog.Logger
	DB   *store.Queries
	Pool *pgxpool.Pool
	RC   *river.Client[pgx.Tx]
}

// New constructs a Service with all required dependencies wired.
func New(
	conf *config.Conf,
	log *slog.Logger,
	db *store.Queries,
	pool *pgxpool.Pool,
	rc *river.Client[pgx.Tx],
) *Service {
	return &Service{
		Conf: conf,
		Log:  log,
		DB:   db,
		Pool: pool,
		RC:   rc,
	}
}
