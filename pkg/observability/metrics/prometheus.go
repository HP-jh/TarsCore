// Package prometheus provides Prometheus-compatible metrics exporter.
package prometheus

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type Exporter struct {
	mu       sync.RWMutex
	counters map[string]int64
	gauges   map[string]float64
	histograms map[string]*HistogramData
}

type HistogramData struct {
	Buckets map[string]int64
	Sum     float64
	Count   int64
}

func NewExporter() *Exporter {
	return &Exporter{
		counters:   make(map[string]int64),
		gauges:     make(map[string]float64),
		histograms: make(map[string]*HistogramData),
	}
}

func (e *Exporter) Inc(counter string, value int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.counters[counter] += value
}

func (e *Exporter) Set(gauge string, value float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gauges[gauge] = value
}

func (e *Exporter) Observe(histogram string, value float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	hd, ok := e.histograms[histogram]
	if !ok {
		hd = &HistogramData{Buckets: make(map[string]int64)}
		e.histograms[histogram] = hd
	}
	hd.Sum += value
	hd.Count++
	bucketKey := fmt.Sprintf("%.1f", value)
	hd.Buckets[bucketKey]++
}

func (e *Exporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	
	for name, val := range e.counters {
		fmt.Fprintf(w, "# HELP %s Counter metric\n# TYPE %s counter\n%s %d\n", 
			formatMetricName(name), name, name, val)
	}
	
	for name, val := range e.gauges {
		fmt.Fprintf(w, "# HELP %s Gauge metric\n# TYPE %s gauge\n%s %.4f\n",
			formatMetricName(name), name, name, val)
	}
	
	for name, hd := range e.histograms {
		fmt.Fprintf(w, "# HELP %s Histogram metric\n# TYPE %s histogram\n",
			formatMetricName(name), name)
		for bucket, count := range hd.Buckets {
			fmt.Fprintf(w, "%s_bucket{le=\"%s\"} %d\n", name, bucket, count)
		}
		fmt.Fprintf(w, "%s_sum %.4f\n", name, hd.Sum)
		fmt.Fprintf(w, "%s_count %d\n", name, hd.Count)
	}
}

func formatMetricName(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}
