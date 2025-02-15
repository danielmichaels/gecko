package riverjobs

import (
	"context"
	"github.com/danielmichaels/doublestag/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"log/slog"
)

type Client struct {
	logger *slog.Logger
	dbPool *pgxpool.Pool
	rc     *river.Client[pgx.Tx]
}

func New(ctx context.Context, logger *slog.Logger, db *pgxpool.Pool, dbtx *store.Queries, workerCount int) (*Client, error) {
	migrator, err := rivermigrate.New(riverpgxv5.New(db), nil)
	if err != nil {
		return nil, err
	}
	res, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	if err != nil {
		return nil, err
	}
	for _, version := range res.Versions {
		logger.Info("riverjobs migrations ran", "direction", res.Direction, "version", version.Version)
	}

	rw := river.NewWorkers()
	river.AddWorker(rw, &SendEmailWorker{Logger: *logger, DB: dbtx})
	rc, err := river.NewClient(riverpgxv5.New(db), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: workerCount},
		},
		Workers: rw,
	})
	if err != nil {
		return nil, err
	}
	return &Client{
		logger: logger,
		dbPool: db,
		rc:     rc,
	}, nil
}

// Close stops the riverqueue worker processes gracefully.
//
// This implements the jobs.Client interface
func (c *Client) Close(ctx context.Context) error {
	err := c.rc.Stop(ctx)
	c.dbPool.Close()
	return err
}

// Work starts the riverqueue worker processes.
//
// This implements the jobs.Client interface
func (c *Client) Work(ctx context.Context) error {
	err := c.rc.Start(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) CancelJob(ctx context.Context, jobID int64) error {
	_, err := c.rc.JobCancel(ctx, jobID)
	if err != nil {
		return err
	}
	return nil
}
