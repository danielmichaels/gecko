package scanner

import (
	"log/slog"

	"github.com/danielmichaels/gecko/internal/store"
)

type Config struct {
	Logger *slog.Logger
	Store  *store.Queries
}

type Scan struct {
	logger *slog.Logger
	store  *store.Queries
}

func NewScanner(cfg Config) *Scan {
	return &Scan{
		logger: cfg.Logger,
		store:  cfg.Store,
	}
}
