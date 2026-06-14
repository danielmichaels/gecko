// Package notify is the channel ("bearer") abstraction for outbound notifications.
// A rendered Notification is dispatched across a tenant's enabled channels; email
// is the only channel today, but Slack/webhook/etc. slot in by implementing Channel
// and registering with the Dispatcher — the digest job that produces notifications
// never changes.
package notify

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Kind classifies a notification so channels (and future per-kind routing) can tell
// a routine summary from an urgent alert. Only the daily digest ships today;
// KindHighImpact is the seam for the phase-2 real-time alert path.
const (
	KindDailyDigest = "daily_digest"
	KindHighImpact  = "high_impact"
)

// Notification is a channel-agnostic, fully-rendered message. HTML is for rich
// channels (email); Text is the fallback every channel can use.
type Notification struct {
	Subject  string
	HTML     string
	Text     string
	Kind     string
	TenantID int32
}

// Recipient is a notification target. Only Email is used today; richer channels add
// their own address fields here later (e.g. SlackUserID) without breaking callers.
type Recipient struct {
	Email string
	Name  string
}

// Channel delivers a Notification to recipients. tx is the caller's transaction so a
// channel can enqueue its delivery atomically with the watermark advance (the email
// channel does this via the River send_email job); channels with no transactional
// step ignore it.
type Channel interface {
	Name() string
	Send(ctx context.Context, tx pgx.Tx, n Notification, recipients []Recipient) error
}

// Dispatcher routes a Notification to the channels named in a tenant's enabled set.
// A channel's failure is collected but does not stop the others — one broken bearer
// must not silence the rest.
type Dispatcher struct {
	channels map[string]Channel
}

// NewDispatcher builds a Dispatcher with the given channels registered by Name().
func NewDispatcher(channels ...Channel) *Dispatcher {
	d := &Dispatcher{channels: make(map[string]Channel, len(channels))}
	for _, c := range channels {
		d.Register(c)
	}
	return d
}

// Register adds (or replaces) a channel keyed by its Name().
func (d *Dispatcher) Register(c Channel) {
	d.channels[c.Name()] = c
}

// Dispatch sends n to every enabled channel that is registered. Unknown enabled
// names are reported as errors (a misconfigured channel should be visible, not
// silently dropped). Per-channel errors are joined; a partial failure still
// delivers the working channels.
func (d *Dispatcher) Dispatch(
	ctx context.Context,
	tx pgx.Tx,
	enabled []string,
	n Notification,
	recipients []Recipient,
) error {
	var errs []error
	for _, name := range enabled {
		c, ok := d.channels[name]
		if !ok {
			errs = append(errs, fmt.Errorf("notify: no channel registered for %q", name))
			continue
		}
		if err := c.Send(ctx, tx, n, recipients); err != nil {
			errs = append(errs, fmt.Errorf("notify: channel %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
