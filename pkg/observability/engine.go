// Package observability provides enterprise-grade metrics, tracing, logging, and alerting.
// Implements OpenTelemetry-compatible interfaces with Prometheus exporters.
package observability

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/HP-jh/TarsCore/pkg/core"
)

// ===== Structured Logger =====

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

func (l LogLevel) String() string {
	return []string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}[l]
}

type Logger struct {
	mu       sync.Mutex
	level    LogLevel
	format   string // json or console
	outputs  []interface{}
	hooks    []HookFunc
}

type HookFunc func(entry *LogEntry) error

type LogEntry struct {
	Timestamp time.Time `json:"ts"`
	Level     string    `json:"level"`
	Message   string    `json:"msg"`
	Caller    string    `json:"caller,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

func NewLogger(level LogLevel, format string) *Logger {
	return &Logger{
		level:  level,
		format: format,
		outputs: []interface{}{os.Stderr},
	}
}

func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	l.log(DEBUG, msg, fields...)
}

func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	l.log(INFO, msg, fields...)
}

func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	l.log(WARN, msg, fields...)
}

func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	l.log(ERROR, msg, fields...)
}

func (l *Logger) Fatal(msg string, fields ...map[string]interface{}) {
	l.log(FATAL, msg, fields...)
	os.Exit(1)
}

func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	return l // simplified - in production would chain fields
}

func (l *Logger) AddHook(hook HookFunc) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hooks = append(l.hooks, hook)
}

func (l *Logger) log(level LogLevel, msg string, extraFields ...map[string]interface{}) {
	if level < l.level {
		return
	}
	
	entry := &LogEntry{
		Timestamp: time.Now(),
		Level:     level.String(),
		Message:   msg,
		Fields:    make(map[string]interface{}),
	}
	
	if len(extraFields) > 0 {
		for k, v := range extraFields[0] {
			entry.Fields[k] = v
		}
	}
	
	// Execute hooks
	l.mu.Lock()
	for _, hook := range l.hooks {
		_ = hook(entry) // ignore errors for non-blocking
	}
	l.mu.Unlock()
	
	// Output to all destinations
	data := fmt.Sprintf("[%s] %s: %s\n", entry.Timestamp.Format(time.RFC3339), entry.Level, entry.Message)
	for _, out := range l.outputs {
		fmt.Fprint(out, data)
	}
}

// ===== Prometheus-Style Metrics =====

type CounterMetric struct {
	name        string
	description string
	value       int64
}

func NewCounter(name, desc string) *CounterMetric {
	return &CounterMetric{name: name, description: desc}
}

func (m *CounterMetric) Inc() { atomic.AddInt64(&m.value, 1) }
func (m *CounterMetric) Value() int64 { return m.value }

type GaugeMetric struct {
	name        string
	description string
	value       float64
}

func NewGauge(name, desc string) *GaugeMetric {
	return &GaugeMetric{name: name, description: desc}
}

func (g *GaugeMetric) Set(v float64) { g.value = v }
func (g *GaugeMetric) Inc()          { g.value++ }
func (g *GaugeMetric) Dec()          { g.value-- }
func (g *GaugeMetric) Value() float64 { return g.value }

type HistogramMetric struct {
	name         string
	description  string
	buckets      []float64
	count        int64
	sum          float64
	currentValue float64
}

func NewHistogram(name, desc string, buckets []float64) *HistogramMetric {
	return &HistogramMetric{name: name, description: desc, buckets: buckets}
}

func (h *HistogramMetric) Observe(v float64) {
	atomic.AddInt64(&h.count, 1)
	h.sum += v
	h.currentValue = v
}

func (h *HistogramMetric) Count() int64  { return h.count }
func (h *HistogramMetric) Sum() float64  { return h.sum }
func (h *HistogramMetric) Avg() float64 {
	if h.count == 0 {
		return 0
	}
	return h.sum / float64(h.count)
}
func (h *HistogramMetric) Latest() float64 { return h.currentValue }

// ===== Distributed Tracing =====

type SpanContext struct {
	TraceID    string
	SpanID     string
	ParentSpan string
	StartTime  time.Time
	EndTime    time.Time
	Attributes map[string]string
}

func NewSpanContext(traceID, spanID string) *SpanContext {
	return &SpanContext{
		TraceID:    traceID,
		SpanID:     spanID,
		StartTime:  time.Now(),
		Attributes: make(map[string]string),
	}
}

func (sc *SpanContext) SetAttribute(key, value string) {
	sc.Attributes[key] = value
}

func (sc *SpanContext) End() {
	sc.EndTime = time.Now()
}

func (sc *SpanContext) Duration() time.Duration {
	return sc.EndTime.Sub(sc.StartTime)
}

type Tracer interface {
	StartSpan(ctx context.Context, name string) (*SpanContext, context.Context)
	EndSpan(span *SpanContext)
	GetCurrentContext(ctx context.Context) *SpanContext
	SetCurrentContext(parentCtx context.Context, span *SpanContext) context.Context
}

type SimpleTracer struct {
	mu      sync.Mutex
	spans   []*SpanContext
	contextKey interface{}
}

func NewSimpleTracer() *SimpleTracer {
	return &SimpleTracer{
		spans:  make([]*SpanContext, 0),
	}
}

func (t *SimpleTracer) StartSpan(ctx context.Context, name string) (*SpanContext, context.Context) {
	traceID := fmt.Sprintf("trace-%d", time.Now().UnixNano())
	spanID := fmt.Sprintf("span-%d", time.Now().UnixMicro())
	span := NewSpanContext(traceID, spanID)
	span.SetAttribute("component", name)
	
	t.mu.Lock()
	t.spans = append(t.spans, span)
	t.mu.Unlock()
	
	newCtx := context.WithValue(ctx, t.contextKey, span)
	return span, newCtx
}

func (t *SimpleTracer) EndSpan(span *SpanContext) {
	span.End()
}

func (t *SimpleTracer) GetCurrentContext(ctx context.Context) *SpanContext {
	if span, ok := ctx.Value(t.contextKey).(*SpanContext); ok {
		return span
	}
	return nil
}

func (t *SimpleTracer) SetCurrentContext(parentCtx context.Context, span *SpanContext) context.Context {
	return context.WithValue(parentCtx, t.contextKey, span)
}

// ===== Smart Alerting System =====

type AlertRule struct {
	Name       string
	MetricName string
	Operator   string // gt, lt, eq
	Threshold  float64
	Duration   time.Duration // must be violated for this long before firing
	Policy     AlertPolicy   // immediate, summary
}

type AlertPolicy int

const (
	ImmediateAlert AlertPolicy = iota
	SummaryAlert
)

type AlertManager struct {
	mu         sync.Mutex
	rules      []AlertRule
	fireCount  map[string]int
	alertHistory []AlertEvent
	maxHistory int
}

type AlertEvent struct {
	Rule      string    `json:"rule"`
	Value     float64   `json:"value"`
	Condition string    `json:"condition"`
	FiredAt   time.Time `json:"fired_at"`
	Status    string    `json:"status"` // fired, resolved
}

func NewAlertManager(maxHistory int) *AlertManager {
	return &AlertManager{
		fireCount:  make(map[string]int),
		maxHistory: maxHistory,
	}
}

func (am *AlertManager) AddRule(rule AlertRule) {
	am.mu.Lock()
	am.rules = append(am.rules, rule)
	am.mu.Unlock()
}

func (am *AlertManager) Check(metric MetricChecker) []AlertEvent {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	var events []AlertEvent
	
	for _, rule := range am.rules {
		value := metric.GetValue(rule.MetricName)
		
		fired := false
		var conditionStr string
		
		switch rule.Operator {
		case "gt":
			fired = value > rule.Threshold
			conditionStr = fmt.Sprintf("%s > %.2f", rule.MetricName, rule.Threshold)
		case "lt":
			fired = value < rule.Threshold
			conditionStr = fmt.Sprintf("%s < %.2f", rule.MetricName, rule.Threshold)
		case "eq":
			fired = value == rule.Threshold
			conditionStr = fmt.Sprintf("%s == %.2f", rule.MetricName, rule.Threshold)
		}
		
		if fired {
			am.fireCount[rule.Name]++
			
			if am.fireCount[rule.Name] >= 3 { // minimum 3 violations
				event := AlertEvent{
					Rule:      rule.Name,
					Value:     value,
					Condition: conditionStr,
					FiredAt:   time.Now(),
					Status:    "fired",
				}
				events = append(events, event)
				
				// Record to history
				am.alertHistory = append(am.alertHistory, event)
				if len(am.alertHistory) > am.maxHistory {
					am.alertHistory = am.alertHistory[len(am.alertHistory)-am.maxHistory:]
				}
			}
		} else {
			// Reset counter if metric recovers
			if am.fireCount[rule.Name] > 0 {
				event := AlertEvent{
					Rule:      rule.Name,
					Value:     value,
					Condition: conditionStr,
					FiredAt:   time.Now(),
					Status:    "resolved",
				}
				events = append(events, event)
				am.fireCount[rule.Name] = 0
			}
		}
	}
	
	return events
}

func (am *AlertManager) GetHistory(n int) []AlertEvent {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	if n > len(am.alertHistory) {
		n = len(am.alertHistory)
	}
	out := make([]AlertEvent, n)
	copy(out, am.alertHistory[len(am.alertHistory)-n:])
	return out
}

// MetricChecker is the interface that actual metrics implement
type MetricChecker interface {
	GetValue(metricName string) float64
}

// ===== Dashboard Data Provider =====

type DashboardProvider struct {
	logger     *Logger
	tracer     Tracer
	counterMetrics  map[string]*CounterMetric
	gaugeMetrics    map[string]*GaugeMetric
	histogramMetrics map[string]*HistogramMetric
	startTime        time.Time
	mu               sync.RWMutex
}

func NewDashboardProvider(logger *Logger, tracer Tracer) *DashboardProvider {
	return &DashboardProvider{
		logger:           logger,
		tracer:           tracer,
		counterMetrics:   make(map[string]*CounterMetric),
		gaugeMetrics:     make(map[string]*GaugeMetric),
		histogramMetrics: make(map[string]*HistogramMetric),
		startTime:        time.Now(),
	}
}

func (dp *DashboardProvider) RegisterCounter(name, desc string) *CounterMetric {
	m := NewCounter(name, desc)
	dp.counterMetrics[name] = m
	return m
}

func (dp *DashboardProvider) RegisterGauge(name, desc string) *GaugeMetric {
	m := NewGauge(name, desc)
	dp.gaugeMetrics[name] = m
	return m
}

func (dp *DashboardProvider) RegisterHistogram(name, desc string, buckets []float64) *HistogramMetric {
	m := NewHistogram(name, desc, buckets)
	dp.histogramMetrics[name] = m
	return m
}

func (dp *DashboardProvider) GetStats() map[string]interface{} {
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	
	stats := map[string]interface{}{
		"uptime":      time.Since(dp.startTime).String(),
		"counters":    make(map[string]int64),
		"gauges":      make(map[string]float64),
		"histograms":  make(map[string]float64),
	}
	
	for k, v := range dp.counterMetrics {
		stats["counters"].(map[string]int64)[k] = v.Value()
	}
	
	for k, v := range dp.gaugeMetrics {
		stats["gauges"].(map[string]float64)[k] = v.Value()
	}
	
	for k, v := range dp.histogramMetrics {
		stats["histograms"].(map[string]float64)[k] = v.Avg()
	}
	
	return stats
}
