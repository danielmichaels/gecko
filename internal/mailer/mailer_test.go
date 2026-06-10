package mailer

import (
	"context"
	"log/slog"
	"testing"

	"github.com/danielmichaels/gecko/internal/config"
)

func TestNew_SelectsDriver(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	tests := []struct {
		name   string
		driver string
		want   Mailer
	}{
		{name: "log", driver: "log", want: (*LogMailer)(nil)},
		{name: "noop", driver: "noop", want: NoopMailer{}},
		{name: "smtp", driver: "smtp", want: (*SmtpMailer)(nil)},
		{name: "unknown falls back to log", driver: "bogus", want: (*LogMailer)(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Conf{}
			cfg.Mail.Driver = tt.driver
			cfg.Mail.SMTPHost = "localhost"
			cfg.Mail.SMTPPort = 1025

			m, err := New(cfg, log)
			if err != nil {
				t.Fatalf("New(%q) error = %v", tt.driver, err)
			}
			if gotType, wantType := typeName(m), typeName(tt.want); gotType != wantType {
				t.Errorf("New(%q) = %s, want %s", tt.driver, gotType, wantType)
			}
		})
	}
}

func TestLogMailer_Send(t *testing.T) {
	m := &LogMailer{Logger: slog.New(slog.DiscardHandler)}
	if err := m.Send(context.Background(), Message{To: "a@b.com", Subject: "hi"}); err != nil {
		t.Errorf("LogMailer.Send error = %v, want nil", err)
	}
}

func TestNoopMailer_Send(t *testing.T) {
	if err := (NoopMailer{}).Send(context.Background(), Message{}); err != nil {
		t.Errorf("NoopMailer.Send error = %v, want nil", err)
	}
}

func typeName(m Mailer) string {
	switch m.(type) {
	case *LogMailer:
		return "*LogMailer"
	case NoopMailer:
		return "NoopMailer"
	case *SmtpMailer:
		return "*SmtpMailer"
	default:
		return "unknown"
	}
}
