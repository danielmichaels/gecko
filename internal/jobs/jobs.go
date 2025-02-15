package jobs

import "context"

type Client interface {
	Close(ctx context.Context) error
	Work(ctx context.Context) error
	CancelJob(ctx context.Context, jobID int64) error
}
