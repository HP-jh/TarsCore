// Package opentelemetry provides OpenTelemetry-compatible tracing exporter.
package opentelemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type Span struct {
	TraceID    string            `json:"trace_id"`
	SpanID     string            `json:"span_id"`
	ParentSpan string            `json:"parent_span,omitempty"`
	Name       string            `json:"name"`
	StartTime  time.Time         `json:"start_time"`
	EndTime    time.Time         `json:"end_time"`
	Status     string            `json:"status"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Children   []*Span           `json:"children,omitempty"`
}

type TraceExporter struct {
	mu     sync.Mutex
	spans  []*Span
	traces map[string][]*Span
}

func NewTraceExporter() *TraceExporter {
	return &TraceExporter{
		spans:  make([]*Span, 0),
		traces: make(map[string][]*Span),
	}
}

func (te *TraceExporter) StartSpan(ctx context.Context, name string) (*Span, context.Context) {
	traceID := fmt.Sprintf("%x", time.Now().UnixNano())
	spanID := fmt.Sprintf("%x", time.Now().UnixMicro())
	
	span := &Span{
		TraceID:   traceID,
		SpanID:    spanID,
		Name:      name,
		StartTime: time.Now(),
		Attributes: make(map[string]string),
	}
	
	newCtx := context.WithValue(ctx, "current-span", span)
	
	te.mu.Lock()
	te.spans = append(te.spans, span)
	te.traces[traceID] = append(te.traces[traceID], span)
	te.mu.Unlock()
	
	return span, newCtx
}

func (te *TraceExporter) EndSpan(span *Span) {
	span.EndTime = time.Now()
	span.Status = "OK"
}

func (te *TraceExporter) GetTraces(limit int) []map[string]interface{} {
	te.mu.Lock()
	defer te.mu.Unlock()
	
	type TraceSummary struct {
		TraceID    string   `json:"trace_id"`
		SpanCount  int      `json:"span_count"`
		DurationMs float64  `json:"duration_ms"`
	}
	
	var summaries []map[string]interface{}
	count := 0
	
	for traceID, spans := range te.traces {
		if count >= limit { break }
		
		var dur float64
		if len(spans) > 0 {
			dur = spans[len(spans)-1].EndTime.Sub(spans[0].StartTime).Milliseconds()
		}
		
		summaries = append(summaries, map[string]interface{}{
			"trace_id":   traceID,
			"span_count": len(spans),
			"duration_ms": dur,
		})
		count++
	}
	
	return summaries
}

func (te *TraceExporter) ExportJSON() ([]byte, error) {
	te.mu.Lock()
	defer te.mu.Unlock()
	
	data := map[string]interface{}{
		"total_spans": len(te.spans),
		"total_traces": len(te.traces),
		"traces": te.traces,
	}
	return json.MarshalIndent(data, "", "  ")
}
