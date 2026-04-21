package cache

import (
	"container/list"
	"sync"
	"time"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Cache is a generic in-memory LRU cache with per-entry expiry and user-based invalidation.
type Cache[K comparable, U comparable, V any] interface {
	// Set inserts or replaces an entry. userID is used for bulk invalidation.
	Set(key K, user U, value V, expiry time.Time)

	// Get returns the cached value if present and not expired, updating its access time.
	Get(key K) (V, bool)

	// Delete removes a single entry by key.
	Delete(key K)

	// DeleteByUser removes all entries associated with the given user ID.
	DeleteByUser(user U)

	// Prune removes all expired entries, returning the count removed.
	Prune() int

	// Stats returns a snapshot of cache statistics.
	Stats() CacheStats
}

type CacheStats struct {
	Hits        int64
	Misses      int64
	Evictions   int64 // LRU pressure evictions (max size exceeded)
	Expirations int64 // TTL-based removals via Prune or lazy on Get
	Size        int   // current entry count
}

type cache[K comparable, U comparable, V any] struct {
	mu      sync.RWMutex
	maxSize int
	now     func() time.Time
	entries map[K]*list.Element
	users   map[U]map[K]struct{}
	order   *list.List
	stats   CacheStats
}

type entry[K comparable, U comparable, V any] struct {
	key    K
	user   U
	value  V
	expiry time.Time
}

var _ Cache[string, string, any] = (*cache[string, string, any])(nil)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func New[K comparable, U comparable, V any](maxSize int) Cache[K, U, V] {
	return &cache[K, U, V]{
		maxSize: maxSize,
		now:     time.Now,
		entries: make(map[K]*list.Element),
		users:   make(map[U]map[K]struct{}),
		order:   list.New(),
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *cache[K, U, V]) Set(key K, user U, value V, expiry time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.entries[key]; exists {
		current := elem.Value.(*entry[K, U, V])
		if current.user != user {
			c.removeUserKey(current.user, key)
			c.addUserKey(user, key)
		}
		current.user = user
		current.value = value
		current.expiry = expiry
		c.order.MoveToFront(elem)
		return
	}

	item := &entry[K, U, V]{
		key:    key,
		user:   user,
		value:  value,
		expiry: expiry,
	}
	elem := c.order.PushFront(item)
	c.entries[key] = elem
	c.addUserKey(user, key)
	c.stats.Size = len(c.entries)
	c.evictOverflow()
}

func (c *cache[K, U, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var zero V
	elem, exists := c.entries[key]
	if !exists {
		c.stats.Misses++
		return zero, false
	}

	item := elem.Value.(*entry[K, U, V])
	if c.isExpired(item) {
		c.deleteElement(elem, false, true)
		c.stats.Misses++
		return zero, false
	}

	c.order.MoveToFront(elem)
	c.stats.Hits++
	return item.value, true
}

func (c *cache[K, U, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.entries[key]; exists {
		c.deleteElement(elem, false, false)
	}
}

func (c *cache[K, U, V]) DeleteByUser(user U) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keys, exists := c.users[user]
	if !exists {
		return
	}
	for key := range keys {
		if elem, ok := c.entries[key]; ok {
			c.deleteElement(elem, false, false)
		}
	}
}

func (c *cache[K, U, V]) Prune() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	var removed int
	for elem := c.order.Back(); elem != nil; {
		prev := elem.Prev()
		item := elem.Value.(*entry[K, U, V])
		if c.isExpired(item) {
			c.deleteElement(elem, false, true)
			removed++
		}
		elem = prev
	}
	return removed
}

func (c *cache[K, U, V]) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	stats.Size = len(c.entries)
	return stats
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (c *cache[K, U, V]) evictOverflow() {
	if c.maxSize <= 0 {
		c.stats.Size = len(c.entries)
		return
	}
	for len(c.entries) > c.maxSize {
		tail := c.order.Back()
		if tail == nil {
			break
		}
		c.deleteElement(tail, true, false)
	}
}

func (c *cache[K, U, V]) deleteElement(elem *list.Element, eviction, expiration bool) {
	item := elem.Value.(*entry[K, U, V])
	delete(c.entries, item.key)
	c.removeUserKey(item.user, item.key)
	c.order.Remove(elem)
	if eviction {
		c.stats.Evictions++
	}
	if expiration {
		c.stats.Expirations++
	}
	c.stats.Size = len(c.entries)
}

func (c *cache[K, U, V]) addUserKey(user U, key K) {
	keys, exists := c.users[user]
	if !exists {
		keys = make(map[K]struct{})
		c.users[user] = keys
	}
	keys[key] = struct{}{}
}

func (c *cache[K, U, V]) removeUserKey(user U, key K) {
	keys, exists := c.users[user]
	if !exists {
		return
	}
	delete(keys, key)
	if len(keys) == 0 {
		delete(c.users, user)
	}
}

func (c *cache[K, U, V]) isExpired(item *entry[K, U, V]) bool {
	return !item.expiry.IsZero() && !item.expiry.After(c.now())
}
