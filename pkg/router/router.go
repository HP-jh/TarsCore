// Package router implements a two-stage smart router for AI backends.
// Stage 1: deterministic static rules (primary, always available).
// Stage 2: ε-greedy bandit optimises auto-branches when multiple backends reachable.
package router

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State is the persisted bandit state.
type State struct {
	Arms      map[string]*Arm `json:"arms"`
	Decisions uint64          `json:"decisions"`
	Epsilon   float64         `json:"epsilon"`
}

// Arm tracks performance metrics for one backend candidate.
type Arm struct {
	Calls     uint64  `json:"calls"`
	Successes uint64  `json:"successes"`
	Failures  uint64  `json:"failures"`
	RewSum    float64 `json:"rew_sum"` // weighted reward sum
	AvgLatMs  float64 `json:"avg_lat_ms"`
}

// Config holds router configuration.
type Config struct {
	Enabled       bool    `json:"enabled"`
	EpsilonStart  float64 `json:"epsilon_start"`  // default 0.1
	EpsilonMin    float64 `json:"epsilon_min"`    // default 0.02
	PersistSec    int     `json:"persist_sec"`    // write interval (default 60)
	MaxEntries    int     `json:"max_entries"`    // memory limit (default 1024)
}

var defaults = Config{
	Enabled:      true,
	EpsilonStart: 0.1,
	EpsilonMin:   0.02,
	PersistSec:   60,
	MaxEntries:   1024,
}

// ===== Internal State =====

var (
	mu      sync.Mutex
	st      = State{Arms: make(map[string]*Arm), Epsilon: defaults.EpsilonStart}
	rng     = rand.New(rand.NewSource(time.Now().UnixNano()))
	stateFn string // path to persist file
)

// Setup sets the persistence file path and loads saved state.
func Setup(stateFile string) {
	stateFn = stateFile
	Load()
}

// Pick selects a backend from the candidate list.
// Returns (backend, wasExplored).
// When candidates ≤ 1, no exploration happens — just return the single option.
func Pick(candidates []string) (string, bool) {
	if len(candidates) <= 1 {
		return candidates[0], false
	}
	mu.Lock()
	defer mu.Unlock()

	// Decay epsilon
	start, min := getBounds()
	if st.Epsilon > min {
		st.Epsilon *= 0.995
		if st.Epsilon < min {
			st.Epsilon = min
		}
	}
	st.Decisions++

	if rng.Float64() < st.Epsilon {
		// Explore: pick randomly
		chosen := candidates[rng.Intn(len(candidates))]
		auditLog("ROUTER_EXPLORE", fmt.Sprintf("ε=%.3f candidate=%s", st.Epsilon, chosen))
		return chosen, true
	}

	// Exploit: best average reward (0.5 prior for cold-start arms)
	best, bestScore := "", -1e9
	for _, c := range candidates {
		arm, exists := st.Arms[c]
		score := 0.5 // prior
		if exists && arm.Calls > 0 {
			score = arm.RewSum / float64(arm.Calls)
			// Skip arms with very low success rate and enough samples
			if arm.Calls >= 5 && float64(arm.Successes)/float64(arm.Calls) < 0.2 {
				score -= 10
			}
		}
		if score > bestScore {
			best, bestScore = c, score
		}
	}
	return best, false
}

// RecordOutcome records a routing result. Non-admin roles get ×0.1 weight
// to prevent feedback manipulation.
func RecordOutcome(backend string, ok bool, latency time.Duration, isAdmin bool) {
	mu.Lock()
	defer mu.Unlock()

	arm, exists := st.Arms[backend]
	if !exists {
		arm = &Arm{}
		st.Arms[backend] = arm
	}
	if len(st.Arms) > defaults.MaxEntries {
		// Evict least-recently-used: simplest is first alphabetical (not perfect but fine)
		delete(st.Arms, minKey(st.Arms))
	}

	weight := 1.0
	if !isAdmin {
		weight = 0.1
	}

	var rew float64
	if ok {
		rew = 1.0 / (1.0 + latency.Seconds())
	} else {
		rew = -1.0
	}

	arm.Calls++
	if ok {
		arm.Successes++
		arm.AvgLatMs = (arm.AvgLatMs*float64(arm.Successes-1) + latency.Milliseconds()) / float64(arm.Successes)
	} else {
		arm.Failures++
	}
	arm.RewSum += rew * weight
}

// Snapshot returns a copy of current state (thread-safe).
func Snapshot() State {
	mu.Lock()
	defer mu.Unlock()
	cp := State{
		Arms:      make(map[string]*Arm, len(st.Arms)),
		Decisions: st.Decisions,
		Epsilon:   st.Epsilon,
	}
	for k, v := range st.Arms {
		cp.Arms[k] = &Arm{
			Calls:     v.Calls,
			Successes: v.Successes,
			Failures:  v.Failures,
			RewSum:    v.RewSum,
			AvgLatMs:  v.AvgLatMs,
		}
	}
	return cp
}

// Load reads persisted state from disk.
func Load() {
	if stateFn == "" {
		return
	}
	b, err := os.ReadFile(stateFn)
	if err != nil {
		return
	}
	var loaded State
	if json.Unmarshal(b, &loaded) == nil && loaded.Arms != nil {
		mu.Lock()
		start, _ := getBounds()
		if loaded.Epsilon <= 0 || loaded.Epsilon > start {
			loaded.Epsilon = start
		}
		loaded.Epsilon = min(loaded.Epsilon, defaults.EpsilonMin)
		st = loaded
		mu.Unlock()
	}
}

// Save writes state to disk.
func Save() error {
	if stateFn == "" {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(stateFn), 0o755)
	return os.WriteFile(stateFn, b, 0o600)
}

// GetState returns current config bounds.
func getBounds() (start, min float64) {
	return defaults.EpsilonStart, defaults.EpsilonMin
}

func minKey(m map[string]*Arm) string {
	k, v := "", -1e9
	for key, arm := range m {
		if arm.Calls < v || v == -1e9 {
			k, v = key, arm.Calls
		}
	}
	return k
}

func auditLog(tag, msg string) {}
func min(a, b float64) float64 { if a < b { return a }; return b }
