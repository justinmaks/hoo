package resolve

import (
	"testing"
	"time"
)

func TestResolverCacheMiss(t *testing.T) {
	r := NewResolver(2, 100, 5*time.Minute)
	defer r.Stop()

	// First lookup returns raw IP (cache miss).
	result := r.Lookup("127.0.0.1")
	if result != "127.0.0.1" {
		t.Errorf("expected raw IP on cache miss, got %s", result)
	}
}

func TestResolverCacheEviction(t *testing.T) {
	r := NewResolver(1, 3, 5*time.Minute)
	defer r.Stop()

	// Manually add entries to fill cache.
	r.mu.Lock()
	r.addEntry("1.1.1.1", "one.one.one.one")
	r.addEntry("8.8.8.8", "dns.google")
	r.addEntry("9.9.9.9", "dns9.quad9.net")
	r.mu.Unlock()

	r.mu.Lock()
	if len(r.cache) != 3 {
		t.Errorf("cache size = %d, want 3", len(r.cache))
	}
	r.mu.Unlock()

	// Adding a 4th should evict LRU.
	r.mu.Lock()
	r.addEntry("1.0.0.1", "one.one.one.one")
	if len(r.cache) != 3 {
		t.Errorf("cache size after eviction = %d, want 3", len(r.cache))
	}
	r.mu.Unlock()
}

func TestResolverNegativeCache(t *testing.T) {
	r := NewResolver(1, 100, 5*time.Minute)
	defer r.Stop()

	// Manually add negative entry.
	r.mu.Lock()
	r.addEntry("192.0.2.1", "")
	r.mu.Unlock()

	// Lookup should return raw IP for negative cache.
	result := r.Lookup("192.0.2.1")
	if result != "192.0.2.1" {
		t.Errorf("expected raw IP for negative cache, got %s", result)
	}
}

func TestResolverTTLExpiry(t *testing.T) {
	r := NewResolver(1, 100, 1*time.Millisecond)
	defer r.Stop()

	r.mu.Lock()
	r.addEntry("1.1.1.1", "one.one.one.one")
	r.mu.Unlock()

	// Wait for TTL to expire.
	time.Sleep(5 * time.Millisecond)

	// Should return raw IP after expiry.
	result := r.Lookup("1.1.1.1")
	if result != "1.1.1.1" {
		t.Errorf("expected raw IP after TTL expiry, got %s", result)
	}
}
