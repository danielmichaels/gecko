package scanner

import (
	"log/slog"

	"github.com/danielmichaels/gecko/internal/dnsclient"
	"github.com/danielmichaels/gecko/internal/observer"
	"github.com/danielmichaels/gecko/internal/store"
)

type Config struct {
	Logger   *slog.Logger
	Store    *store.Queries
	Resolver dnsclient.Resolver // nil in unit tests → NewScanner falls back to dnsclient.New()
	// Identity is the scan identity used to stamp observations. Left zero in unit
	// tests; emission is skipped then.
	Identity observer.DomainIdentity
}

type Scan struct {
	logger   *slog.Logger
	store    *store.Queries
	resolver dnsclient.Resolver
	identity observer.DomainIdentity
}

func NewScanner(cfg Config) *Scan {
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = dnsclient.New()
	}
	return &Scan{
		logger:   cfg.Logger,
		store:    cfg.Store,
		resolver: resolver,
		identity: cfg.Identity,
	}
}
