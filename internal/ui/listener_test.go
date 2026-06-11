package ui_test

import (
	"context"
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/testhelpers"
	"github.com/danielmichaels/gecko/internal/ui"
	"github.com/jackc/pgx/v5"
)

// TestObservationListenerRepublishesToBroker asserts the listener turns a raw
// Postgres NOTIFY on domain_observations into an ObservationEvent fanned out to
// broker subscribers on the matching tenant scope.
func TestObservationListenerRepublishesToBroker(t *testing.T) {
	testhelpers.ParallelDBTest(t)
	ctx := context.Background()
	pc, err := testhelpers.CreatePostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to create postgres container: %v", err)
	}
	defer pc.Close(ctx)

	broker := ui.NewSSEBroker()
	_, events := broker.Subscribe("tenant:7")

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	connect := func(c context.Context) (*pgx.Conn, error) {
		return pgx.Connect(c, pc.ConnectionString)
	}
	go ui.StartObservationListener(runCtx, connect, broker, nil)

	// LISTEN/NOTIFY only reaches sessions already listening, and the listener
	// LISTENs asynchronously. Fire repeatedly until the event arrives or we give
	// up, rather than racing a one-shot notify against listener startup.
	payload := `{"tenant_id":7,"domain_id":3,"domain_uid":"dom_live","domain_name":"live.example.com","scan_id":9,"entity_type":"a_record","change_type":"created"}`
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(5 * time.Second)
	for {
		if _, err := pc.Pool.Exec(ctx, "SELECT pg_notify('domain_observations', $1)", payload); err != nil {
			t.Fatalf("pg_notify: %v", err)
		}
		select {
		case evt := <-events:
			if evt.TenantID != 7 || evt.DomainUID != "dom_live" {
				t.Fatalf("event = %+v, want tenant 7 domain dom_live", evt)
			}
			if evt.ScanID != 9 || evt.EntityType != "a_record" {
				t.Errorf("event = %+v, want scan 9 entity a_record", evt)
			}
			return
		case <-ticker.C:
		case <-deadline:
			t.Fatal("listener never republished the notification to the broker")
		}
	}
}
