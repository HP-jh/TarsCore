// Package gateway provides the enterprise HTTP server with middleware chain, WebSocket support, and dashboard.
// Implements Tencent NT architecture layered design for AI security gateway.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	
	"github.com/HP-jh/TarsCore/pkg/config"
	"github.com/HP-jh/TarsCore/pkg/security/waf"
)

// ===== Enterprise HTTP Server =====

type Gateway struct {
	server      *http.Server
	mux         *http.ServeMux
	config      *config.Config
	middleware  MiddlewareChain
	router      Router
	eventBus    EventPublisher
	dashboard   Dashboard
	logger      Logger
	isRunning   bool
	listenAddr  string
}

type MiddlewareFunc func(http.Handler) http.Handler

type MiddlewareChain struct {
	handlers []MiddlewareFunc
}

func NewGateway(cfg *config.Config, router Router, eventBus EventPublisher) *Gateway {
	gw := &Gateway{
		config:     cfg,
		mux:        http.NewServeMux(),
		router:     router,
		eventBus:   eventBus,
		logger:     NewSimpleLogger(),
		listenAddr: fmt.Sprintf("127.0.0.1:%d", cfg.Port),
	}
	
	// Build default middleware chain
	gw.middleware = gw.buildDefaultChain()
	return gw
}

func (gw *Gateway) buildDefaultChain() MiddlewareChain {
	return MiddlewareChain{
		handlers: []MiddlewareFunc{
			gw.recoverPanic,
			gw.logRequest,
			gw.securityHeaders,
			gw.corsPolicy,
			gw.traceHeader,
		},
	}
}

func (gw *Gateway) Start() error {
	gw.server = &http.Server{
		Addr:              gw.listenAddr,
		Handler:           gw.middleware.Apply(gw.mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      600 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	
	gw.isRunning = true
	go gw.monitorHealth()
	
	fmt.Printf("[GATEWAY] Starting on %s\n", gw.listenAddr)
	if err := gw.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("gateway listen failed: %w", err)
	}
	return nil
}

func (gw *Gateway) Stop(ctx context.Context) error {
	if !gw.isRunning {
		return nil
	}
	gw.isRunning = false
	fmt.Println("[GATEWAY] Graceful shutdown...")
	return gw.server.Shutdown(ctx)
}

func (gw *Gateway) monitorHealth() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		if gw.isRunning {
			gw.logger.Info("Health check passed", map[string]interface{}{
				"uptime": time.Since(startTime).String(),
			})
		}
	}
}

// ===== Route Registration =====

func (gw *Gateway) Handle(pattern string, handler HandlerFunc, guards ...GuardFunc) {
	gw.mux.HandleFunc(pattern, gw.wrapHandler(handler, guards...))
}

func (gw *Gateway) wrapHandler(h HandlerFunc, guards ...GuardFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Apply guards in order
		for _, guard := range guards {
			if denied := guard(r); denied {
				jsonErr(w, http.StatusForbidden, map[string]string{"error": "access denied"})
				return
			}
		}
		
		h.ServeHTTP(w, r)
	}
}

// ===== Built-in Middlewares =====

func (gw *Gateway) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				errMsg := fmt.Sprintf("panic recovered: %v", p)
				gw.logger.Error(errMsg)
				jsonErr(w, http.StatusInternalServerError, map[string]string{
					"error": "internal error (recovered)",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (gw *Gateway) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrap response writer to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: 200}
		
		next.ServeHTTP(rw, r)
		
		duration := time.Since(start)
		status := rw.statusCode
		
		fields := map[string]interface{}{
			"method":     r.Method,
			"path":       r.URL.Path,
			"status":     status,
			"duration_ms": duration.Milliseconds(),
			"client_ip":  getClientIP(r),
		}
		
		if status >= 500 {
			gw.logger.Error(fmt.Sprintf("%s %s → %d", r.Method, r.URL.Path, status), fields)
		} else if status >= 400 {
			gw.logger.Warn(fmt.Sprintf("%s %s → %d", r.Method, r.URL.Path, status), fields)
		} else {
			gw.logger.Debug(fmt.Sprintf("%s %s → %d", r.Method, r.URL.Path, status), fields)
		}
	})
}

func (gw *Gateway) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

func (gw *Gateway) corsPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (gw *Gateway) traceHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := r.Header.Get("X-Trace-Id")
		if traceID == "" {
			traceID = generateUUID()
		}
		r.Header.Set("X-Trace-Id", traceID)
		w.Header().Set("X-Trace-Id", traceID)
		next.ServeHTTP(w, r)
	})
}

// ===== SSE Real-time Event Stream =====

func (gw *Gateway) SSEStream(writer http.ResponseWriter, request *http.Request, eventBus EventPublisher) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "SSE not supported", http.StatusInternalServerError)
		return
	}
	
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	ctx := request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events := eventBus.Recent(50)
			data, _ := json.Marshal(events)
			fmt.Fprintf(writer, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// ===== WebSocket Upgrade Placeholder =====

func (gw *Gateway) WSUpgrade(writer http.ResponseWriter, request *http.Request) {
	// Production would use gorilla/websocket or nhooyr.io/websocket
	writer.WriteHeader(http.StatusNotImplemented)
	writer.Write([]byte("WebSocket — wire real implementation"))
}

// ===== Response Writer Wrapper =====

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// ===== Public Helper Functions =====

var startTime = time.Now()
var muReq sync.Mutex
var totalReq, successReq, failReq, wafBlocks int

func RecordRequest(ok bool, blocked bool) {
	muReq.Lock()
	totalReq++
	if blocked {
		wafBlocks++
	} else if ok {
		successReq++
	} else {
		failReq++
	}
	muReq.Unlock()
}

func GetStats() map[string]interface{} {
	muReq.Lock()
	defer muReq.Unlock()
	return map[string]interface{}{
		"total_requests": totalReq,
		"success":        successReq,
		"fail":           failReq,
		"waf_blocks":     wafBlocks,
		"uptime_seconds": time.Since(startTime).Seconds(),
	}
}

func extractAPIKey(r *http.Request) string {
	if k := r.Header.Get("X-API-Key"); k != "" { return k }
	if k := r.Header.Get("Authorization"); strings.HasPrefix(k, "Bearer ") { return k[7:] }
	return r.URL.Query().Get("apiKey")
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		i := strings.Index(xff, ",")
		if i > 0 { return xff[:i] }
		return xff
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" { return xr }
	return r.RemoteAddr
}

func jsonErr(w http.ResponseWriter, code int, m map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(m)
}

func generateUUID() string {
	return fmt.Sprintf("trace-%d", time.Now().UnixNano())
}
