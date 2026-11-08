// Package circuit implements the three-state circuit breaker pattern.
// Each provider gets an independent breaker: closed → open → half-open → closed/reopen.
// Circuit state affects routing availability only, never the security chain.
package circuit

import (
	"fmt"
	"sync"
	"time"
)

// State is the breaker's current mode.
type State int

const (
	Closed State = iota // normal operation
	Open                // consecutive failures threshold hit; reject outbound requests immediately
	HalfOpen            // cooldown elapsed; probe one request to test recovery
)

func (s State) String() string {
	switch s {
	case Closed: return "closed"
	case Open: return "open"
	case HalfOpen: return "half-open"
	default: return "unknown"
	}
}

// Breaker tracks failure count, open time, and half-open probe status.
type Breaker struct {
	state     State
	failures  int        // consecutive failures in closed state
	openedAt  time.Time  // when transitioned to open
	busy      bool       // half-open: probe request in flight?
}

var (
	mu    sync.Mutex
	table = map[string]*Breaker{}
)

// DefaultParams returns default thresholds.
func DefaultParams() (threshold int, openSec, probeSec int) {
	return 5, 30, 60 // 5 failures → 30s open → 60s probe interval
}

// Allow decides whether a request should proceed for the given ID.
// Returns true if allowed (closed or half-open cooldown passed).
func Allow(id string) (bool, string) {
	mu.Lock()
	defer mu.Unlock()

	b, exists := table[id]
	if !exists {
		table[id] = &Breaker{state: Closed}
		return true, ""
	}

	switch b.state {
	case Closed:
		return true, ""

	case Open:
		_, openSec, _ := DefaultParams()
		if time.Since(b.openedAt) >= time.Duration(openSec)*time.Second {
			b.state = HalfOpen
			b.busy = true
			auditLog("PROVIDER_CIRCUIT_HALF_OPEN", id)
			return true, "probe_request"
		}
		auditLog("PROVIDER_CIRCUIT_OPEN", fmt.Sprintf("%s still in open state", id))
		return false, "circuit_open"

	case HalfOpen:
		if b.busy {
			return false, "probe_in_flight"
		}
		b.busy = true
		return true, "probe_request"

	default:
		return false, "unknown_state"
	}
}

// Record records a single outbound result.
// ok=true resets to closed; ok=false increments failure counter.
func Record(id string, ok bool) {
	threshold, _, _ := DefaultParams()
	mu.Lock()
	defer mu.Unlock()

	b, exists := table[id]
	if !exists {
		b = &Breaker{state: Closed}
		table[id] = b
	}

	prev := b.state

	if ok {
		switch b.state {
		case HalfOpen:
			b.state = Closed
			b.failures = 0
			b.busy = false
			auditLog("PROVIDER_CIRCUIT_RECOVERED", fmt.Sprintf("%s recovered to closed", id))
		case Closed:
			b.failures = 0 // reset on success
		}
	} else {
		switch b.state {
		case Closed:
			b.failures++
			if b.failures >= threshold {
				b.state = Open
				b.openedAt = time.Now()
				auditLog("PROVIDER_CIRCUIT_OPEN",
					fmt.Sprintf("%s tripped after %d failures", id, b.failures))
			}
		case HalfOpen:
			b.state = Open
			b.openedAt = time.Now()
			auditLog("PROVIDER_CIRCUIT_REOPENED",
				fmt.Sprintf("%s probe failed, reopened", id))
		}
	}
}

// Status returns snapshot of all breakers.
func Status() map[string]struct {
	State   string `json:"state"`
	Fails   int    `json:"failures"`
	Message string `json:"message"`
} {
	mu.Lock()
	defer mu.Unlock()
	out := make(map[string]struct {
		State   string `json:"state"`
		Fails   int    `json:"failures"`
		Message string `json:"message"`
	})
	for id, b := range table {
		out[id] = struct {
			State   string `json:"state"`
			Fails   int    `json:"failures"`
			Message string `json:"message"`
		}{
			State:   b.state.String(),
			Fails:   b.failures,
			Message: stateMessage(b),
		}
	}
	return out
}

func stateMessage(b *Breaker) string {
	switch b.state {
	case Closed:
		return fmt.Sprintf("consecutive_failures=%d", b.failures)
	case Open:
		dur := time.Since(b.openedAt).Seconds()
		return fmt.Sprintf("opened %.0fs ago", dur)
	case HalfOpen:
		return "probe in progress or waiting"
	default:
		return "unknown"
	}
}

func auditLog(tag, msg string) {}
