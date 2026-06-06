package dnsclient

import (
	"container/list"
	"sync"
	"time"
)

// cacheKey identifies a cached DNS answer by record type and FQDN.
type cacheKey struct {
	fqdn  string
	qtype uint16
}

// cacheEntry is a cached resolution: the answer strings, the three-way status, and
// when the entry expires. It is shared by the in-process L1 and the Postgres L2.
type cacheEntry struct {
	expiresAt time.Time
	answers   []string
	status    ResolutionStatus
}

// l1Cache is a fixed-size, TTL-aware LRU in front of the Postgres L2. It collapses
// repeated lookups within a single process without a database round-trip.
type l1Cache struct {
	ll       *list.List
	items    map[cacheKey]*list.Element
	capacity int
	mu       sync.Mutex
}

type l1Item struct {
	key   cacheKey
	entry cacheEntry
}

func newL1Cache(capacity int) *l1Cache {
	return &l1Cache{
		capacity: capacity,
		ll:       list.New(),
		items:    make(map[cacheKey]*list.Element),
	}
}

// get returns the entry for key when present and unexpired. An expired entry is
// removed and reported as a miss.
func (c *l1Cache) get(key cacheKey, now time.Time) (cacheEntry, bool) {
	if c.capacity <= 0 {
		return cacheEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return cacheEntry{}, false
	}
	item := el.Value.(*l1Item)
	if !item.entry.expiresAt.After(now) {
		c.removeElement(el)
		return cacheEntry{}, false
	}
	c.ll.MoveToFront(el)
	return item.entry, true
}

// set stores entry under key, evicting the least-recently-used entry when the
// cache is over capacity.
func (c *l1Cache) set(key cacheKey, entry cacheEntry) {
	if c.capacity <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		el.Value.(*l1Item).entry = entry
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&l1Item{key: key, entry: entry})
	c.items[key] = el
	if c.ll.Len() > c.capacity {
		c.removeElement(c.ll.Back())
	}
}

func (c *l1Cache) removeElement(el *list.Element) {
	if el == nil {
		return
	}
	c.ll.Remove(el)
	delete(c.items, el.Value.(*l1Item).key)
}
