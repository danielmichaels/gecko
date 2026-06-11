package ui_test

import (
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/ui"
)

func recv(t *testing.T, ch <-chan ui.ObservationEvent) (ui.ObservationEvent, bool) {
	t.Helper()
	select {
	case evt, ok := <-ch:
		return evt, ok
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
		return ui.ObservationEvent{}, false
	}
}

func TestSSEBrokerSubscribeReceivesPublish(t *testing.T) {
	t.Parallel()
	b := ui.NewSSEBroker()
	_, ch := b.Subscribe("tenant:1")

	want := ui.ObservationEvent{TenantID: 1, DomainUID: "dom_abc", ChangeType: "created"}
	b.Publish("tenant:1", want)

	got, ok := recv(t, ch)
	if !ok {
		t.Fatal("channel closed unexpectedly")
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestSSEBrokerScopesAreIsolated(t *testing.T) {
	t.Parallel()
	b := ui.NewSSEBroker()
	_, ch := b.Subscribe("tenant:1")

	b.Publish("tenant:2", ui.ObservationEvent{TenantID: 2})

	select {
	case evt := <-ch:
		t.Fatalf("received cross-scope event: %+v", evt)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSSEBrokerFanOutToAllSubscribers(t *testing.T) {
	t.Parallel()
	b := ui.NewSSEBroker()
	_, ch1 := b.Subscribe("tenant:1")
	_, ch2 := b.Subscribe("tenant:1")

	want := ui.ObservationEvent{TenantID: 1, DomainUID: "dom_xyz"}
	b.Publish("tenant:1", want)

	for _, ch := range []<-chan ui.ObservationEvent{ch1, ch2} {
		got, ok := recv(t, ch)
		if !ok || got != want {
			t.Fatalf("subscriber missed event: got %+v ok=%v", got, ok)
		}
	}
}

func TestSSEBrokerUnsubscribeStopsDelivery(t *testing.T) {
	t.Parallel()
	b := ui.NewSSEBroker()
	id, ch := b.Subscribe("tenant:1")
	b.Unsubscribe("tenant:1", id)

	b.Publish("tenant:1", ui.ObservationEvent{TenantID: 1})

	if _, ok := <-ch; ok {
		t.Fatal("expected channel closed after unsubscribe")
	}
}

func TestSSEBrokerPublishNoSubscribersIsNoop(t *testing.T) {
	t.Parallel()
	b := ui.NewSSEBroker()
	// Must not panic or block.
	b.Publish("tenant:999", ui.ObservationEvent{TenantID: 999})
}

func TestSSEBrokerFullBufferDropsWithoutBlocking(t *testing.T) {
	t.Parallel()
	b := ui.NewSSEBroker()
	b.Subscribe("tenant:1") // never drained

	done := make(chan struct{})
	go func() {
		for range 1000 {
			b.Publish("tenant:1", ui.ObservationEvent{TenantID: 1})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a full subscriber buffer")
	}
}
