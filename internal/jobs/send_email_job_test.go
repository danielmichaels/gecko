package jobs

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/danielmichaels/gecko/internal/mailer"
	"github.com/riverqueue/river"
)

type spyMailer struct {
	got mailer.Message
	err error
}

func (m *spyMailer) Send(_ context.Context, msg mailer.Message) error {
	m.got = msg
	return m.err
}

func TestSendEmailWorker_Work_CallsMailer(t *testing.T) {
	spy := &spyMailer{}
	w := &SendEmailWorker{Logger: *slog.New(slog.DiscardHandler), Mailer: spy}

	args := SendEmailArgs{To: "a@b.com", Subject: "Reset", HTML: "<p>hi</p>", Text: "hi"}
	if err := w.Work(context.Background(), &river.Job[SendEmailArgs]{Args: args}); err != nil {
		t.Fatalf("Work error = %v", err)
	}
	if spy.got.To != "a@b.com" || spy.got.Subject != "Reset" {
		t.Errorf("mailer got %+v, want To=a@b.com Subject=Reset", spy.got)
	}
	if spy.got.HTML != "<p>hi</p>" || spy.got.Text != "hi" {
		t.Errorf("mailer body got HTML=%q Text=%q", spy.got.HTML, spy.got.Text)
	}
}

func TestSendEmailWorker_Work_PropagatesError(t *testing.T) {
	wantErr := errors.New("smtp down")
	spy := &spyMailer{err: wantErr}
	w := &SendEmailWorker{Logger: *slog.New(slog.DiscardHandler), Mailer: spy}

	err := w.Work(
		context.Background(),
		&river.Job[SendEmailArgs]{Args: SendEmailArgs{To: "a@b.com"}},
	)
	if !errors.Is(err, wantErr) {
		t.Errorf("Work error = %v, want wrap of %v", err, wantErr)
	}
}
