package cache

import (
	"sync"
	"time"
)

type Manager struct {
	mu    sync.RWMutex
	caches map[string]*Cache
	defaultTTL time.Duration
}

func NewManager(defaultTTL time.Duration) *Manager {
	return &Manager{
		caches: make(map[string]*Cache),
		defaultTTL: defaultTTL,
	}
}

func (m *Manager) GetOrCreate(name string, capacity int) *Cache {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if c, ok := m.caches[name]; ok {
		return c
	}
	
	c := New(m.defaultTTL, capacity)
	m.caches[name] = c
	return c
}
