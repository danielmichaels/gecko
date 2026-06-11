package ui

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

const observationChannel = "domain_observations"

// ObservationConnector opens a fresh, dedicated connection for the listener. It
// must NOT hand back a connection borrowed from the request pool — a lifelong
// LISTEN would permanently reduce that pool's capacity. Returning a standalone
// pgx.Conn also makes reconnecting after a drop a simple "call it again".
type ObservationConnector func(context.Context) (*pgx.Conn, error)

// observationNotification is the wire shape emitted by the recorder's pg_notify.
// It mirrors observer's notify payload; kept local so the ui package does not
// import observer.
type observationNotification struct {
	DomainUID  string `json:"domain_uid"`
	DomainName string `json:"domain_name"`
	EntityType string `json:"entity_type"`
	ChangeType string `json:"change_type"`
	ScanID     int64  `json:"scan_id"`
	TenantID   int32  `json:"tenant_id"`
}

// StartObservationListener LISTENs on the domain_observations channel and
// republishes every notification to the broker on the originating tenant's
// scope. It blocks until ctx is cancelled, reconnecting with capped backoff on
// any connection loss. Run it in a goroutine from the server process. Delivery
// is best-effort: notifications fired while the listener is reconnecting are
// missed (the DB stays the source of truth).
func StartObservationListener(
	ctx context.Context,
	connect ObservationConnector,
	broker *SSEBroker,
	log *slog.Logger,
) {
	if log == nil {
		log = slog.Default()
	}
	const minBackoff, maxBackoff = time.Second, 30 * time.Second
	backoff := minBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		err := listenOnce(ctx, connect, broker, log)
		if ctx.Err() != nil {
			return
		}
		log.Warn(
			"observation listener disconnected; reconnecting",
			"error",
			err,
			"backoff",
			backoff,
		)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// listenOnce opens a connection, LISTENs, and pumps notifications into the broker
// until the connection or context fails. It returns the error that ended the
// loop so the caller can decide whether to reconnect.
func listenOnce(
	ctx context.Context,
	connect ObservationConnector,
	broker *SSEBroker,
	log *slog.Logger,
) error {
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, "LISTEN "+observationChannel); err != nil {
		return err
	}
	log.Info("observation listener connected", "channel", observationChannel)

	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var note observationNotification
		if err := json.Unmarshal([]byte(n.Payload), &note); err != nil {
			log.Warn("observation listener: bad payload", "payload", n.Payload, "error", err)
			continue
		}
		// observationNotification and ObservationEvent share the same fields (the
		// former only adds snake_case json tags for decoding the payload), so a
		// direct conversion avoids a field-by-field copy.
		broker.Publish(observationScope(note.TenantID), ObservationEvent(note))
	}
}
