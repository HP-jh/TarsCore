package circuit

import (
	"sync"
	"time"
)

type State int

const (
	Closed State = iota
	Open
	HalfOpen
)

func (s State) String() string {
	switch s {
	case Closed: return "closed"
	case Open: return "open"
	case HalfOpen: return "half-open"
	default: return "unknown"
	}
}

type Breaker struct {
	mu       sync.Mutex
	state    State
	failures int
	openedAt time.Time
	halfOpen bool
}

var (
	table = map[string]*Breaker{}
	mu    sync.Mutex
)

func Allow(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	
	b, exists := table[id]
	if !exists {
		table[id] = &Breaker{state: Closed}
		return true
	}
	
	switch b.state {
	case Closed:
		return true
	case Open:
		if time.Since(b.openedAt) >= 30*time.Second {
			b.state = HalfOpen
			b.halfOpen = true
			return true
		}
		return false
	case HalfOpen:
		if !b.halfOpen {
			b.halfOpen = true
			return true
		}
		return false
	default:
		return false
	}
}

func Record(id string, ok bool) {
	mu.Lock()
	defer mu.Unlock()
	
	b, exists := table[id]
	if !exists {
		return
	}
	
	if ok {
		if b.state == HalfOpen {
			b.state = Closed
			b.failures = 0
		} else if b.state == Closed {
			b.failures = 0
		}
	} else {
		b.failures++
		if b.failures >= 5 {
			b.state = Open
			b.openedAt = time.Now()
		}
	}
}

func Status(id string) (State, int) {
	mu.Lock()
	defer mu.Unlock()
	if b, ok := table[id]; ok {
		return b.state, b.failures
	}
	return Closed, 0
}
