package notify

import (
	"context"
	"fmt"

	"github.com/danielmichaels/gecko/internal/mailer"
	"github.com/jackc/pgx/v5"
)

// EmailEnqueuer queues one outbound email on the caller's transaction. It mirrors
// service.EmailEnqueuer: the production impl wraps the River send_email job, so the
// notify package never depends on jobs/river directly (the concrete enqueuer is
// supplied at wiring time).
type EmailEnqueuer interface {
	EnqueueEmail(ctx context.Context, tx pgx.Tx, msg mailer.Message) error
}

// EmailChannel delivers a Notification as one email per recipient via the injected
// enqueuer. It adds no transport of its own — it reuses the existing send_email
// worker — so it is a thin fan-out over Notification -> mailer.Message.
type EmailChannel struct {
	enq EmailEnqueuer
}

// NewEmailChannel builds the email channel over an enqueuer.
func NewEmailChannel(enq EmailEnqueuer) *EmailChannel {
	return &EmailChannel{enq: enq}
}

func (c *EmailChannel) Name() string { return "email" }

// Send enqueues one email per recipient on tx. The send_email worker takes a single
// To, so a tenant digest fans out to one job per owner/manager; all are enqueued in
// the caller's transaction and commit atomically with the watermark advance.
func (c *EmailChannel) Send(
	ctx context.Context,
	tx pgx.Tx,
	n Notification,
	recipients []Recipient,
) error {
	for _, r := range recipients {
		msg := mailer.Message{
			To:      r.Email,
			Subject: n.Subject,
			HTML:    n.HTML,
			Text:    n.Text,
		}
		if err := c.enq.EnqueueEmail(ctx, tx, msg); err != nil {
			return fmt.Errorf("enqueue email to %s: %w", r.Email, err)
		}
	}
	return nil
}
