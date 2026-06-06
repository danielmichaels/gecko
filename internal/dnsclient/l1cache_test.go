package dnsclient

import (
	"testing"
	"time"
)

func entryAt(ttl time.Duration, now time.Time, answers ...string) cacheEntry {
	return cacheEntry{answers: answers, status: ResolutionData, expiresAt: now.Add(ttl)}
}

func TestL1Cache_SetThenGet(t *testing.T) {
	now := time.Now()
	c := newL1Cache(8)
	key := cacheKey{qtype: 1, fqdn: "example.com."}
	c.set(key, entryAt(time.Minute, now, "192.0.2.1"))

	got, ok := c.get(key, now)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got.answers) != 1 || got.answers[0] != "192.0.2.1" {
		t.Fatalf("unexpected answers: %v", got.answers)
	}
}

func TestL1Cache_MissOnAbsentKey(t *testing.T) {
	c := newL1Cache(8)
	if _, ok := c.get(cacheKey{qtype: 1, fqdn: "absent."}, time.Now()); ok {
		t.Fatal("expected miss for absent key")
	}
}

func TestL1Cache_ExpiredEntryMisses(t *testing.T) {
	now := time.Now()
	c := newL1Cache(8)
	key := cacheKey{qtype: 1, fqdn: "example.com."}
	c.set(key, entryAt(time.Minute, now, "192.0.2.1"))

	if _, ok := c.get(key, now.Add(2*time.Minute)); ok {
		t.Fatal("expected expired entry to miss")
	}
	// A second get confirms the expired entry was evicted, not merely filtered.
	if _, ok := c.get(key, now); ok {
		t.Fatal("expected expired entry to have been removed")
	}
}

func TestL1Cache_EvictsLeastRecentlyUsed(t *testing.T) {
	now := time.Now()
	c := newL1Cache(2)
	a := cacheKey{qtype: 1, fqdn: "a."}
	b := cacheKey{qtype: 1, fqdn: "b."}
	d := cacheKey{qtype: 1, fqdn: "c."}
	c.set(a, entryAt(time.Minute, now, "a"))
	c.set(b, entryAt(time.Minute, now, "b"))

	// Touch a so b becomes least-recently-used, then overflow.
	if _, ok := c.get(a, now); !ok {
		t.Fatal("expected a to be present")
	}
	c.set(d, entryAt(time.Minute, now, "c"))

	if _, ok := c.get(b, now); ok {
		t.Fatal("expected b (LRU) to have been evicted")
	}
	if _, ok := c.get(a, now); !ok {
		t.Fatal("expected a to survive eviction")
	}
	if _, ok := c.get(d, now); !ok {
		t.Fatal("expected newest entry c to be present")
	}
}

func TestL1Cache_ZeroCapacityDisabled(t *testing.T) {
	now := time.Now()
	c := newL1Cache(0)
	key := cacheKey{qtype: 1, fqdn: "example.com."}
	c.set(key, entryAt(time.Minute, now, "192.0.2.1"))
	if _, ok := c.get(key, now); ok {
		t.Fatal("expected zero-capacity cache to store nothing")
	}
}
