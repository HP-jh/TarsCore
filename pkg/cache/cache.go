package cache

import (
	"sync"
	"time"
)

type Item struct {
	Value     interface{}
	ExpiresAt time.Time
}

type Cache struct {
	mu       sync.RWMutex
	items    map[string]*Item
	ttl      time.Duration
	capacity int
}

func New(ttl time.Duration, capacity int) *Cache {
	return &Cache{ttl: ttl, capacity: capacity, items: make(map[string]*Item)}
}

func (c *Cache) Set(key string, value interface{}, t time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	exp := time.Now().Add(t)
	if t <= 0 {
		exp = time.Now().Add(c.ttl)
	}
	
	if len(c.items) >= c.capacity {
		var oldestKey string
		var oldestExp time.Time
		for k, v := range c.items {
			if v.ExpiresAt.Before(oldestExp) || oldestKey == "" {
				oldestKey = k
				oldestExp = v.ExpiresAt
			}
		}
		delete(c.items, oldestKey)
	}
	
	c.items[key] = &Item{Value: value, ExpiresAt: exp}
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	item, ok := c.items[key]
	if !ok || time.Now().After(item.ExpiresAt) {
		return nil, false
	}
	return item.Value, true
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

func (c *Cache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}
