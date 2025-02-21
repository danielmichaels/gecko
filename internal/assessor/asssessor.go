package assessor

import (
	"github.com/danielmichaels/doublestag/internal/store"
	"log/slog"
	"time"
)

// Output interface to ensure all assessors return a structured result
type Output interface {
	GetBaseResult() AssessmentResultBase
}

type Config struct {
	Logger *slog.Logger
	Store  *store.Queries
}

type Assess struct {
	logger *slog.Logger
	store  *store.Queries
}

func NewAssessor(cfg Config) *Assess {
	return &Assess{
		logger: cfg.Logger,
		store:  cfg.Store,
	}
}

type AssessmentResultBase struct {
	Domain       string    `json:"domain"`        // Domain being assessed
	AssessorType string    `json:"assessor_type"` // Type of assessor (e.g., "DanglingCNAMEAssessor")
	Timestamp    time.Time `json:"timestamp"`     // Time of assessment
	Severity     string    `json:"severity"`      // Severity of finding (e.g., "High", "Medium", "Low", "Info", "None")
	Message      string    `json:"message"`       // Human-readable message summarizing the finding
	RawData      interface {
	} `json:"raw_data,omitempty"` // Optional: Raw data related to the finding (e.g., specific records involved)
}

// GetBaseResult implementation - to satisfy the Output interface
func (r AssessmentResultBase) GetBaseResult() AssessmentResultBase {
	return r
}
