package ui

import (
	"strconv"
	"sync"
	"sync/atomic"
)

// observationScope is the broker scope a tenant's browser streams subscribe to.
// Events are routed by tenant; per-domain filtering happens in the stream
// handler (the detail page subscribes to the same tenant scope and ignores
// events for other domains).
func observationScope(tenantID int32) string {
	return "tenant:" + strconv.Itoa(int(tenantID))
}

// subscriberBuffer bounds each subscriber's channel. A browser that falls behind
// has events dropped rather than blocking the publisher — the DB stays the
// source of truth, and a page reload reconciles any missed update.
const subscriberBuffer = 32

// ObservationEvent is the identity of a single domain change, fanned out from the
// Postgres LISTEN/NOTIFY listener to every browser stream on the tenant scope.
// It carries identity only (no rendered HTML): the row HTML embeds a per-session
// CSRF token and role-gated controls, so each stream handler renders its own.
type ObservationEvent struct {
	DomainUID  string
	DomainName string
	EntityType string
	ChangeType string
	ScanID     int64
	TenantID   int32
}

// SSEBroker is a scoped pub/sub hub fanning ObservationEvents out to all browser
// streams subscribed to a scope. Publish is non-blocking: a full subscriber
// buffer drops the event.
type SSEBroker struct {
	subscribers map[string]map[string]chan ObservationEvent
	nextID      atomic.Uint64
	mu          sync.RWMutex
}

// NewSSEBroker returns an empty broker ready for subscribers.
func NewSSEBroker() *SSEBroker {
	return &SSEBroker{subscribers: make(map[string]map[string]chan ObservationEvent)}
}

// Subscribe registers a new subscriber on scope and returns its id plus the
// channel events arrive on. Unsubscribe with the returned id to stop delivery
// and close the channel.
func (b *SSEBroker) Subscribe(scope string) (string, <-chan ObservationEvent) {
	id := strconv.FormatUint(b.nextID.Add(1), 10)
	ch := make(chan ObservationEvent, subscriberBuffer)

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subscribers[scope] == nil {
		b.subscribers[scope] = make(map[string]chan ObservationEvent)
	}
	b.subscribers[scope][id] = ch
	return id, ch
}

// Unsubscribe removes the subscriber and closes its channel. It is a no-op for an
// unknown scope/id.
func (b *SSEBroker) Unsubscribe(scope, id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subscribers[scope]
	if subs == nil {
		return
	}
	if ch, ok := subs[id]; ok {
		close(ch)
		delete(subs, id)
	}
	if len(subs) == 0 {
		delete(b.subscribers, scope)
	}
}

// Publish fans evt out to every subscriber on scope. Delivery is non-blocking: a
// subscriber whose buffer is full silently drops the event.
func (b *SSEBroker) Publish(scope string, evt ObservationEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subscribers[scope] {
		select {
		case ch <- evt:
		default:
		}
	}
}
