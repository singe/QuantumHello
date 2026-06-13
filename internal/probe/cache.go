package probe

import (
	"sync"
	"time"
)

type Cache struct {
	mu    sync.RWMutex
	items map[string]cacheItem
}

type cacheItem struct {
	result    Result
	expiresAt time.Time
}

func NewCache() *Cache {
	return &Cache{items: make(map[string]cacheItem)}
}

func (c *Cache) Get(key string) (Result, bool) {
	c.mu.RLock()
	item, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		return Result{}, false
	}
	if time.Now().After(item.expiresAt) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		return Result{}, false
	}
	return item.result, true
}

func (c *Cache) Store(key string, result Result) {
	c.StoreWithTTL(key, result, cacheTTLFor(result))
}

func (c *Cache) StoreWithTTL(key string, result Result, ttl time.Duration) {
	c.mu.Lock()
	c.items[key] = cacheItem{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}

func cacheTTLFor(result Result) time.Duration {
	switch result.Status {
	case StatusSupported, StatusNotSupported, StatusNoTLS13, StatusBlockedTarget, StatusCertError, StatusInvalidInput:
		return 5 * time.Minute
	default:
		return 1 * time.Minute
	}
}
