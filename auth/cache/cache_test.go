package cache

import (
	"testing"
	"time"

	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestCacheSetGetAndStats(t *testing.T) {
	c := New[string, string, int](2)

	c.Set("key-1", "user-1", 42, time.Time{})

	value, ok := c.Get("key-1")
	require.True(t, ok)
	assert.Equal(t, 42, value)

	_, ok = c.Get("missing")
	assert.False(t, ok)

	stats := c.Stats()
	assert.EqualValues(t, 1, stats.Hits)
	assert.EqualValues(t, 1, stats.Misses)
	assert.Equal(t, 1, stats.Size)
}

func TestCacheDeleteByUser(t *testing.T) {
	c := New[string, string, int](0)

	c.Set("key-1", "user-1", 1, time.Time{})
	c.Set("key-2", "user-1", 2, time.Time{})
	c.Set("key-3", "user-2", 3, time.Time{})

	c.DeleteByUser("user-1")

	_, ok := c.Get("key-1")
	assert.False(t, ok)
	_, ok = c.Get("key-2")
	assert.False(t, ok)
	value, ok := c.Get("key-3")
	require.True(t, ok)
	assert.Equal(t, 3, value)
	assert.Equal(t, 1, c.Stats().Size)
}

func TestCacheExpiresOnGet(t *testing.T) {
	c := New[string, string, int](1)
	impl := c.(*cache[string, string, int])
	now := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	impl.now = func() time.Time { return now }

	c.Set("key-1", "user-1", 1, now.Add(time.Minute))
	impl.now = func() time.Time { return now.Add(2 * time.Minute) }

	_, ok := c.Get("key-1")
	assert.False(t, ok)
	assert.Equal(t, 0, c.Stats().Size)

	stats := c.Stats()
	assert.EqualValues(t, 1, stats.Misses)
	assert.EqualValues(t, 1, stats.Expirations)
	assert.Equal(t, 0, stats.Size)
}

func TestCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c := New[string, string, int](2)

	c.Set("key-1", "user-1", 1, time.Time{})
	c.Set("key-2", "user-1", 2, time.Time{})
	_, ok := c.Get("key-1")
	require.True(t, ok)

	c.Set("key-3", "user-2", 3, time.Time{})

	_, ok = c.Get("key-2")
	assert.False(t, ok)
	value, ok := c.Get("key-1")
	require.True(t, ok)
	assert.Equal(t, 1, value)
	value, ok = c.Get("key-3")
	require.True(t, ok)
	assert.Equal(t, 3, value)

	stats := c.Stats()
	assert.EqualValues(t, 1, stats.Evictions)
	assert.Equal(t, 2, stats.Size)
}

func TestCachePruneRemovesExpiredEntries(t *testing.T) {
	c := New[string, string, int](0)
	impl := c.(*cache[string, string, int])
	now := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)
	impl.now = func() time.Time { return now }

	c.Set("expired", "user-1", 1, now.Add(-time.Minute))
	c.Set("active", "user-1", 2, now.Add(time.Minute))

	removed := c.Prune()
	assert.Equal(t, 1, removed)
	assert.Equal(t, 1, c.Stats().Size)

	value, ok := c.Get("active")
	require.True(t, ok)
	assert.Equal(t, 2, value)

	stats := c.Stats()
	assert.EqualValues(t, 1, stats.Expirations)
	assert.Equal(t, 1, stats.Size)
}
