package scanner

import (
	"log/slog"

	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
)

type Config struct {
	Logger *slog.Logger
	Store  *store.Queries
	// Identity is the scan identity used to stamp observations. Left zero in unit
	// tests; emission is skipped then.
	Identity observer.DomainIdentity
}

type Scan struct {
	logger   *slog.Logger
	store    *store.Queries
	identity observer.DomainIdentity
}

func NewScanner(cfg Config) *Scan {
	return &Scan{
		logger:   cfg.Logger,
		store:    cfg.Store,
		identity: cfg.Identity,
	}
}
