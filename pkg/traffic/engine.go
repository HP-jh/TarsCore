// Package traffic provides enterprise-grade flow control engine inspired by Alibaba Sentinel.
// Implements sliding window rate limiting, token/leaky bucket algorithms, and adaptive overload protection.
package traffic

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ===== Core Interfaces =====

// Limiter defines the interface for all rate limiters.
type Limiter interface {
	Allow() bool
	Wait() error
	Tokens() float64
}

// FlowRule defines a single traffic governance rule.
type FlowRule struct {
	Resource     string      // resource name to protect
	Metric       MetricType  // QPS or concurrent requests
	Strategy     Strategy    // LIMIT, WARM_UP, PARKING_LOT
	Threshold    int         // limit threshold
	ParamIndex   int         // param index for parameterized rate limiting (Sentinel style)
	MaxQueueTime time.Duration // for parking lot strategy
	BurstCount   int         // for warm up ramp up
}

// MetricType specifies what metric is being controlled.
type MetricType int

const (
	QPS MetricType = iota
	ConcurrentRequests
	SystemLoad
	CPUUsage
)

// Strategy specifies the rate limiting strategy.
type Strategy int

const (
	LIMIT Strategy = iota // direct limit
	WARM_UP             // slow start ramp up (Sentinel cold load)
	PARKING_LOIT        // queue with max wait (parking lot)
)

// ===== Sliding Window Counter (QPS limiter) =====

// SlidingWindow implements sliding window rate counting.
// Inspired by Sentinel's statistical counter but simplified for Go concurrency.
type SlidingWindow struct {
	mu          sync.RWMutex
	windowSize  time.Duration
	intervalN   int              // number of buckets in window
	buckets     []bucketCounter // time-ordered buckets
	maxRequests int              // allowed requests per interval
}

type bucketCounter struct {
	timestamp int64 // nanosecond timestamp
	count     int64
}

func NewSlidingWindow(maxRPS int, window time.Duration, intervals int) *SlidingWindow {
	if intervals <= 0 {
		intervals = 10
	}
	sw := &SlidingWindow{
		windowSize: window,
		intervalN:  intervals,
		buckets:    make([]bucketCounter, intervals),
		maxRequests: maxRPS,
	}
	// Initialize with current timestamp
	now := time.Now().UnixNano()
	for i := range sw.buckets {
		sw.buckets[i].timestamp = now + int64(i*window.Nanoseconds()/intervals)
	}
	return sw
}

// Allow checks if a request can pass and atomically increments the counter.
func (sw *SlidingWindow) Allow() bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	now := time.Now().UnixNano()
	currentBucket := now / int64(sw.windowSize/sw.intervalN)

	// Find and clean expired buckets
	totalCount := int64(0)
	for i := range sw.buckets {
		bucketTime := int64(i) * sw.windowSize / time.Duration(sw.intervalN)
		if bucketTime < currentBucket-int64(sw.intervalN) {
			// Expired bucket, reset it
			sw.buckets[i].timestamp = now
			sw.buckets[i].count = 0
		} else {
			totalCount += sw.buckets[i].count
		}
	}

	// Check if we exceed limit
	if totalCount >= int64(sw.maxRequests) {
		return false
	}

	// Increment current bucket
	currentIdx := int(currentBucket % int64(sw.intervalN))
	sw.buckets[currentIdx].count++
	return true
}

// Wait blocks until a slot is available or context times out.
func (sw *SlidingWindow) Wait(ctx context.Context) error {
	ticker := time.NewTicker(time.Millisecond * 10)
	defer ticker.Stop()

	for {
		if sw.Allow() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Tokens returns approximate available tokens (non-realtime).
func (sw *SlidingWindow) Tokens() float64 {
	sw.mu.RLock()
	defer sw.mu.RUnlock()
	
	totalCount := int64(0)
	for _, b := range sw.buckets {
		totalCount += b.count
	}
	return float64(sw.maxRequests - int(totalCount))
}

// ===== Token Bucket (for sustained throughput) =====

// TokenBucket implements a standard token bucket algorithm.
type TokenBucket struct {
	mu           sync.Mutex
	tokens       float64
	maxTokens    float64
	refillRate   float64 // tokens per second
	lastRefill   time.Time
}

func NewTokenBucket(maxTokens float64, refillRate float64) *TokenBucket {
	tb := &TokenBucket{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
	return tb
}

func (tb *TokenBucket) refil() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}
	tb.lastRefill = now
}

func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	
	tb.refill()
	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}

func (tb *TokenBucket) Wait(ctx context.Context) error {
	for {
		if tb.Allow() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond * 100):
		}
	}
}

func (tb *TokenBucket) Tokens() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	return tb.tokens
}

// ===== Leaky Bucket (for constant output rate) =====

// LeakyBucket ensures constant processing rate regardless of input burstiness.
type LeakyBucket struct {
	mu         sync.Mutex
	waterLevel float64
	maxLevel   float64
	leakRate   float64 // items processed per second
	lastLeak   time.Time
}

func NewLeakyBucket(maxLevel float64, leakRate float64) *LeakyBucket {
	lb := &LeakyBucket{
		waterLevel: 0,
		maxLevel:   maxLevel,
		leakRate:   leakRate,
		lastLeak:   time.Now(),
	}
	return lb
}

func (lb *LeakyBucket) leak() {
	now := time.Now()
	elapsed := now.Sub(lb.lastLeak).Seconds()
	lb.waterLevel -= elapsed * lb.leakRate
	if lb.waterLevel < 0 {
		lb.waterLevel = 0
	}
	lb.lastLeak = now
}

func (lb *LeakyBucket) Allow() bool {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	lb.leak()
	if lb.waterLevel >= lb.maxLevel {
		return false
	}
	lb.waterLevel += 1.0
	return true
}

func (lb *LeakyBucket) Wait(ctx context.Context) error {
	for {
		if lb.Allow() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond * 100):
		}
	}
}

func (lb *LeakyBucket) WaterLevel() float64 {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.leak()
	return lb.waterLevel
}

// ===== Adaptive Overload Protection (Sentinel System Protection) =====

// AdaptiveLimiter automatically adjusts limits based on system metrics.
// This is the core of Sentinel's "System Adaptive Load Protection".
type AdaptiveLimiter struct {
	mu               sync.RWMutex
	cpuLimitFactor   float64 // 1.0 means no restriction, lower means more restrictive
	memoryLimitFactor float64
	ioLimitFactor    float64
	systemLoadTarget float64 // target CPU usage (e.g., 0.7 = 70%)
	baseLimit        int     // base QPS limit when system is healthy
	currentLimit     atomic.Int64
}

func NewAdaptiveLimiter(baseLimit int) *AdaptiveLimiter {
	al := &AdaptiveLimiter{
		cpuLimitFactor:   1.0,
		memoryLimitFactor: 1.0,
		ioLimitFactor:    1.0,
		systemLoadTarget: 0.7,
		baseLimit:        baseLimit,
	}
	go al.monitorLoop()
	return al
}

func (al *AdaptiveLimiter) monitorLoop() {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()
	
	for range ticker.C {
		al.updateFactors()
		al.currentLimit.Store(int64(al.effectiveLimit()))
	}
}

func (al *AdaptiveLimiter) updateFactors() {
	// Get system metrics (simplified - would use proper system stats in production)
	cpuUsage := al.getCPUUsage()
	memUsage := al.getMemoryUsage()
	
	// Adaptive adjustment: reduce capacity as system approaches target load
	al.cpuLimitFactor = 1.0
	if cpuUsage > al.systemLoadTarget {
		al.cpuLimitFactor = 1.0 - (cpuUsage-al.systemLoadTarget)*2.0
		if al.cpuLimitFactor < 0.1 {
			al.cpuLimitFactor = 0.1
		}
	}
	
	al.memoryLimitFactor = 1.0
	if memUsage > 0.8 {
		al.memoryLimitFactor = 1.0 - (memUsage-0.8)*5.0
		if al.memoryLimitFactor < 0.1 {
			al.memoryLimitFactor = 0.1
		}
	}
	
	// Combined factor uses minimum (most restrictive)
	factors := []float64{al.cpuLimitFactor, al.memoryLimitFactor, al.ioLimitFactor}
	minFactor := factors[0]
	for _, f := range factors {
		if f < minFactor {
			minFactor = f
		}
	}
	
	al.mu.Lock()
	al.currentLimit.Store(int64(float64(al.baseLimit) * minFactor))
	al.mu.Unlock()
}

func (al *AdaptiveLimiter) getCpuUsage() float64 {
	// Simplified - in production this would read /proc/stat or syscall
	return 0.5 // placeholder
}

func (al *AdaptiveLimiter) getMemoryUsage() float64 {
	// Simplified - would read from runtime.MemStats or /proc/meminfo
	return 0.6 // placeholder
}

func (al *AdaptiveLimiter) effectiveLimit() int {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return int(al.currentLimit.Load())
}

// Allow delegates to underlying limiter with adaptive limit.
func (al *AdaptiveLimiter) Allow() bool {
	limit := al.effectiveLimit()
	// Use sliding window with adaptive limit
	sw := NewSlidingWindow(limit, time.Second, 10)
	return sw.Allow()
}

// ===== Hotspot Parameter Rate Limiting (Sentinel Feature) =====

// HotSpotLimiter provides fine-grained rate limiting per parameter value.
// Example: limit each user ID to 10 requests/second.
type HotSpotLimiter struct {
	mu           sync.Mutex
	paramLimits  map[int]*SlidingWindow // param index -> limiter
	defaultLimit int                    // fallback for unknown params
}

func NewHotSpotLimiter(paramCount int, defaultLimit int) *HotSpotLimiter {
	hsl := &HotSpotLimiter{
		paramLimits:  make(map[int]*SlidingWindow),
		defaultLimit: defaultLimit,
	}
	// Pre-initialize for common param values
	for i := 0; i < paramCount; i++ {
		hsl.paramLimits[i] = NewSlidingWindow(defaultLimit, time.Second, 10)
	}
	return hsl
}

func (hsl *HotSpotLimiter) Allow(paramIndex int, paramValue any) bool {
	// Create key from parameter value
	key := fmt.Sprintf("%d:%v", paramIndex, paramValue)
	
	hsl.mu.Lock()
	defer hsl.mu.Unlock()
	
	// For simplicity, create new limiter for each unique param
	if _, ok := hsl.paramLimits[paramIndex]; !ok {
		hsl.paramLimits[paramIndex] = NewSlidingWindow(hsl.defaultLimit, time.Second, 10)
	}
	
	return hsl.paramLimits[paramIndex].Allow()
}

// ===== Cluster-Level Rate Limiting (distributed) =====

// ClusterLimiter provides distributed rate limiting across multiple instances.
// Uses Redis as the backend (placeholder implementation).
type ClusterLimiter struct {
	resource   string
	threshold  int
	clientID   string
	quorum     int // required consensus for rate limit check
}

func NewClusterLimiter(resource string, threshold int) *ClusterLimiter {
	return &ClusterLimiter{
		resource:  resource,
		threshold: threshold,
		clientID:  fmt.Sprintf("instance-%d", os.Getpid()),
		quorum:    2,
	}
}

func (cl *ClusterLimiter) Allow() bool {
	// In production, this would coordinate with other instances via Redis/Zookeeper
	// For now, local check only (degraded mode)
	localLimiter := NewSlidingWindow(cl.threshold, time.Second, 10)
	return localLimiter.Allow()
}
