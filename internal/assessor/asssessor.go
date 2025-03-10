package assessor

import (
	"github.com/danielmichaels/gecko/internal/store"
	"log/slog"
)

type Config struct {
	Logger *slog.Logger
	Store  *store.Queries
}

type Assessor struct {
	logger *slog.Logger
	store  *store.Queries
}

func NewAssessor(cfg Config) *Assessor {
	return &Assessor{
		logger: cfg.Logger,
		store:  cfg.Store,
	}
}
