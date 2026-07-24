package jobs

import (
	"context"
	"errors"
	"fmt"

	"github.com/danielmichaels/gecko/internal/mailer"
	"github.com/danielmichaels/gecko/internal/notify"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/riverqueue/river"
)

func loadDigestRecipients(
	ctx context.Context,
	st *store.Queries,
	tenantID int32,
) ([]notify.Recipient, error) {
	rows, err := st.UsersListDigestRecipientsByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list recipients: %w", err)
	}
	out := make([]notify.Recipient, 0, len(rows))
	for _, r := range rows {
		out = append(out, notify.Recipient{Email: r.Email, Name: textOrEmpty(r.Name)})
	}
	return out, nil
}

func loadHighImpactItems(
	ctx context.Context,
	st *store.Queries,
	tenantID int32,
	since, until pgtype.Timestamptz,
	limit int,
) ([]notify.HighImpactItem, error) {
	rows, err := st.ObservationsDigestHighImpactByTenant(
		ctx,
		store.ObservationsDigestHighImpactByTenantParams{
			TenantID: tenantID,
			Since:    since,
			Until:    until,
			RowLimit: int32(limit),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list high-impact: %w", err)
	}
	out := make([]notify.HighImpactItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, notify.HighImpactItem{
			DomainName: r.DomainName,
			EntityType: r.EntityType,
			ChangeType: r.ChangeType,
			Severity:   ifaceText(r.Severity),
			Status:     ifaceText(r.Status),
			ObservedAt: r.ObservedAt.Time,
		})
	}
	return out, nil
}

func ifaceText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func textOrEmpty(t pgtype.Text) string {
	if t.Valid {
		return t.String
	}
	return ""
}

type riverEmailEnqueuer struct{}

func (riverEmailEnqueuer) EnqueueEmail(ctx context.Context, tx pgx.Tx, msg mailer.Message) error {
	rc := river.ClientFromContext[pgx.Tx](ctx)
	if rc == nil {
		return errors.New("no river client in context")
	}
	_, err := rc.InsertTx(ctx, tx, SendEmailArgs{
		To:      msg.To,
		Subject: msg.Subject,
		HTML:    msg.HTML,
		Text:    msg.Text,
	}, nil)
	return err
}
