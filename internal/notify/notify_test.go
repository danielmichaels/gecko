package notify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/danielmichaels/gecko/internal/mailer"
	"github.com/jackc/pgx/v5"
)

// recordingChannel records the notifications it is asked to send and optionally
// fails, so dispatch behaviour can be asserted without a real bearer.
type recordingChannel struct {
	name string
	sent []Notification
	fail error
}

func (c *recordingChannel) Name() string { return c.name }

func (c *recordingChannel) Send(_ context.Context, _ pgx.Tx, n Notification, _ []Recipient) error {
	if c.fail != nil {
		return c.fail
	}
	c.sent = append(c.sent, n)
	return nil
}

func TestDispatcher_DispatchesToEnabledChannels(t *testing.T) {
	email := &recordingChannel{name: "email"}
	slack := &recordingChannel{name: "slack"}
	d := NewDispatcher(email, slack)

	n := Notification{Subject: "hi", Kind: KindDailyDigest}
	if err := d.Dispatch(context.Background(), nil, []string{"email"}, n, nil); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(email.sent) != 1 {
		t.Errorf("email sent = %d, want 1", len(email.sent))
	}
	if len(slack.sent) != 0 {
		t.Errorf("slack sent = %d, want 0 (not enabled)", len(slack.sent))
	}
}

func TestDispatcher_FailingChannelDoesNotBlockOthers(t *testing.T) {
	boom := errors.New("boom")
	bad := &recordingChannel{name: "email", fail: boom}
	good := &recordingChannel{name: "slack"}
	d := NewDispatcher(bad, good)

	err := d.Dispatch(
		context.Background(),
		nil,
		[]string{"email", "slack"},
		Notification{Subject: "hi"},
		nil,
	)
	if err == nil {
		t.Fatal("Dispatch err = nil, want the failing channel's error surfaced")
	}
	if !errors.Is(err, boom) {
		t.Errorf("Dispatch err = %v, want it to wrap %v", err, boom)
	}
	// The healthy channel still delivered despite the other failing.
	if len(good.sent) != 1 {
		t.Errorf("slack sent = %d, want 1 (delivered despite email failing)", len(good.sent))
	}
}

func TestDispatcher_UnknownChannelIsReported(t *testing.T) {
	d := NewDispatcher(&recordingChannel{name: "email"})
	err := d.Dispatch(context.Background(), nil, []string{"webhook"}, Notification{}, nil)
	if err == nil {
		t.Fatal("Dispatch err = nil, want an error for an unregistered channel")
	}
	if !strings.Contains(err.Error(), "webhook") {
		t.Errorf("Dispatch err = %v, want it to name the unknown channel", err)
	}
}

// recordingEnqueuer records each enqueued email so the email channel's fan-out can
// be asserted without River.
type recordingEnqueuer struct {
	msgs []mailer.Message
}

func (e *recordingEnqueuer) EnqueueEmail(_ context.Context, _ pgx.Tx, msg mailer.Message) error {
	e.msgs = append(e.msgs, msg)
	return nil
}

func TestEmailChannel_OneMessagePerRecipient(t *testing.T) {
	enq := &recordingEnqueuer{}
	c := NewEmailChannel(enq)

	n := Notification{Subject: "digest", HTML: "<p>x</p>", Text: "x"}
	recipients := []Recipient{
		{Email: "a@example.com"},
		{Email: "b@example.com"},
	}
	if err := c.Send(context.Background(), nil, n, recipients); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(enq.msgs) != 2 {
		t.Fatalf("enqueued = %d, want 2 (one per recipient)", len(enq.msgs))
	}
	if enq.msgs[0].To != "a@example.com" || enq.msgs[1].To != "b@example.com" {
		t.Errorf("recipients = %q, %q", enq.msgs[0].To, enq.msgs[1].To)
	}
	if enq.msgs[0].Subject != "digest" || enq.msgs[0].HTML != "<p>x</p>" {
		t.Errorf("message body not carried through: %+v", enq.msgs[0])
	}
	if c.Name() != "email" {
		t.Errorf("Name() = %q, want email", c.Name())
	}
}
