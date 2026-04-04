package resolve

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	DefaultWorkers  = 8
	DefaultCacheMax = 4096
	DefaultTTL      = 5 * time.Minute
	lookupTimeout   = 2 * time.Second
)

// entry is a single cache entry.
type entry struct {
	hostname string
	negative bool // true if lookup failed
	expires  time.Time

	// LRU doubly-linked list pointers.
	prev, next *entry
	key        string
}

// Resolver performs async reverse DNS lookups with LRU caching.
type Resolver struct {
	mu       sync.Mutex
	cache    map[string]*entry
	maxSize  int
	ttl      time.Duration
	head     *entry // most recently used
	tail     *entry // least recently used

	requests chan string
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewResolver creates a resolver with the given worker count, cache size, and TTL.
func NewResolver(workers, cacheMax int, ttl time.Duration) *Resolver {
	if workers <= 0 {
		workers = DefaultWorkers
	}
	if cacheMax <= 0 {
		cacheMax = DefaultCacheMax
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	ctx, cancel := context.WithCancel(context.Background())

	r := &Resolver{
		cache:    make(map[string]*entry, cacheMax),
		maxSize:  cacheMax,
		ttl:      ttl,
		requests: make(chan string, cacheMax),
		cancel:   cancel,
	}

	// Start worker pool.
	r.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go r.worker(ctx)
	}

	return r
}

// Lookup returns the cached hostname for an IP, or the raw IP string if not resolved yet.
// It enqueues a lookup if the IP is not in cache or expired.
func (r *Resolver) Lookup(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if e, ok := r.cache[ip]; ok {
		if time.Now().Before(e.expires) {
			r.moveToFront(e)
			if e.negative {
				return ip
			}
			return e.hostname
		}
		// Expired — remove and re-enqueue.
		r.removeEntry(e)
	}

	// Enqueue lookup (non-blocking).
	select {
	case r.requests <- ip:
	default:
		// Channel full, skip this lookup.
	}

	return ip
}

// Stop shuts down the resolver and waits for workers to finish.
func (r *Resolver) Stop() {
	r.cancel()
	r.wg.Wait()
}

func (r *Resolver) worker(ctx context.Context) {
	defer r.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-r.requests:
			// Check if already cached (another worker may have resolved it).
			r.mu.Lock()
			if e, ok := r.cache[ip]; ok && time.Now().Before(e.expires) {
				r.mu.Unlock()
				continue
			}
			r.mu.Unlock()

			hostname := r.doLookup(ctx, ip)

			r.mu.Lock()
			r.addEntry(ip, hostname)
			r.mu.Unlock()
		}
	}
}

func (r *Resolver) doLookup(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	resolver := &net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "" // will be stored as negative
	}

	// Remove trailing dot from FQDN.
	name := names[0]
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

func (r *Resolver) addEntry(ip, hostname string) {
	// Evict LRU if at capacity.
	for len(r.cache) >= r.maxSize {
		r.evictLRU()
	}

	e := &entry{
		hostname: hostname,
		negative: hostname == "",
		expires:  time.Now().Add(r.ttl),
		key:      ip,
	}

	r.cache[ip] = e
	r.pushFront(e)
}

func (r *Resolver) removeEntry(e *entry) {
	delete(r.cache, e.key)
	r.unlink(e)
}

func (r *Resolver) evictLRU() {
	if r.tail == nil {
		return
	}
	r.removeEntry(r.tail)
}

// LRU list operations.

func (r *Resolver) pushFront(e *entry) {
	e.prev = nil
	e.next = r.head
	if r.head != nil {
		r.head.prev = e
	}
	r.head = e
	if r.tail == nil {
		r.tail = e
	}
}

func (r *Resolver) moveToFront(e *entry) {
	if e == r.head {
		return
	}
	r.unlink(e)
	r.pushFront(e)
}

func (r *Resolver) unlink(e *entry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		r.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		r.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}
