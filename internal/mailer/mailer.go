// Package mailer is the transport seam for outbound email. The concrete Mailer
// is selected at startup from config (MAIL_DRIVER) and injected into the River
// send_email worker — it is never called inline on a request path.
package mailer

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/danielmichaels/gecko/internal/config"
	gomail "github.com/wneessen/go-mail"
)

// Message is the data contract for a single outbound email.
type Message struct {
	To      string
	Subject string
	HTML    string
	Text    string
}

// Mailer sends a Message. Implementations: SmtpMailer (prod), LogMailer (dev),
// NoopMailer (tests).
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

var (
	_ Mailer = (*SmtpMailer)(nil)
	_ Mailer = (*LogMailer)(nil)
	_ Mailer = NoopMailer{}
)

// New returns the Mailer for the configured driver. An unknown driver falls
// back to LogMailer so a typo never silently drops mail in a way that looks
// like success in production.
func New(cfg *config.Conf, log *slog.Logger) (Mailer, error) {
	switch cfg.Mail.Driver {
	case "noop":
		return NoopMailer{}, nil
	case "smtp":
		return &SmtpMailer{
			host: cfg.Mail.SMTPHost,
			port: cfg.Mail.SMTPPort,
			user: cfg.Mail.SMTPUser,
			pass: cfg.Mail.SMTPPass,
			from: cfg.Mail.FromAddr,
		}, nil
	default:
		return &LogMailer{Logger: log}, nil
	}
}

// NoopMailer discards every message; used in tests.
type NoopMailer struct{}

func (NoopMailer) Send(_ context.Context, _ Message) error { return nil }

// LogMailer logs the envelope and discards the message; the dev default so the
// local stack and CI need no SMTP server.
type LogMailer struct{ Logger *slog.Logger }

func (m *LogMailer) Send(_ context.Context, msg Message) error {
	m.Logger.Info("mailer: (log driver) email not sent", "to", msg.To, "subject", msg.Subject)
	return nil
}

// SmtpMailer delivers over SMTP via go-mail. Used when MAIL_DRIVER=smtp.
type SmtpMailer struct {
	host string
	user string
	pass string
	from string
	port int
}

func (m *SmtpMailer) Send(ctx context.Context, msg Message) error {
	gm := gomail.NewMsg()
	if err := gm.From(m.from); err != nil {
		return fmt.Errorf("mailer: set from: %w", err)
	}
	if err := gm.To(msg.To); err != nil {
		return fmt.Errorf("mailer: set to: %w", err)
	}
	gm.Subject(msg.Subject)
	if msg.HTML != "" {
		gm.SetBodyString(gomail.TypeTextHTML, msg.HTML)
		if msg.Text != "" {
			gm.AddAlternativeString(gomail.TypeTextPlain, msg.Text)
		}
	} else {
		gm.SetBodyString(gomail.TypeTextPlain, msg.Text)
	}

	opts := []gomail.Option{gomail.WithPort(m.port)}
	if m.user != "" {
		opts = append(opts, gomail.WithSMTPAuth(gomail.SMTPAuthPlain))
		opts = append(opts, gomail.WithUsername(m.user))
		opts = append(opts, gomail.WithPassword(m.pass))
	} else {
		opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
	}

	client, err := gomail.NewClient(m.host, opts...)
	if err != nil {
		return fmt.Errorf("mailer: new client: %w", err)
	}
	if err := client.DialAndSendWithContext(ctx, gm); err != nil {
		return fmt.Errorf("mailer: dial and send: %w", err)
	}
	return nil
}
