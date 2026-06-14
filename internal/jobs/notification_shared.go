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

// loadDigestRecipients returns a tenant's notification recipients (active
// owners/managers who have not opted out). Shared by the daily digest and the
// high-impact alert sweep so both honour the same recipient and opt-out rules.
func loadDigestRecipients(
	ctx context.Context,
	st *store.Queries,
	tenantID int32,
) ([]notify.Recipient, error) {
	rows, err := st.UsersListDigestRecipientsByTenant(
		ctx,
		pgtype.Int4{Int32: tenantID, Valid: true},
	)
	if err != nil {
		return nil, fmt.Errorf("list recipients: %w", err)
	}
	out := make([]notify.Recipient, 0, len(rows))
	for _, r := range rows {
		out = append(out, notify.Recipient{Email: r.Email, Name: textOrEmpty(r.Name)})
	}
	return out, nil
}

// loadHighImpactItems returns the critical/high-severity changes for a tenant over
// (since, until], capped by limit. Shared by the digest's high-impact section and
// the alert sweep.
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

// ifaceText coerces a sqlc interface{} column (payload->>'x' projects as untyped
// text) to a string, tolerating a NULL (nil) value.
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

// riverEmailEnqueuer satisfies notify.EmailEnqueuer by inserting a send_email job on
// the caller's transaction, reusing exactly the path riverScheduler.EnqueueEmail
// uses. The River client comes from context (populated inside a running worker), so
// the email channel stays decoupled from the client lifecycle.
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
