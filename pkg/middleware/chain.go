// Package middleware provides the gateway middleware chain.
// Ordered: panic recovery → dynamic defense → rate limit → security headers → WAF → auth → CORS → trace.
package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/HP-jh/TarsCore/pkg/security/waf"
	"github.com/HP-jh/TarsCore/pkg/auth"
)

const maxBodyBytes = int64(5 << 20) // 5 MB

// Chain builds a single http.Handler that applies all middleware in order.
func Chain(cfg Config, handlers ...Handler) http.Handler {
	var h http.Handler = handlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(handlers) > 0 {
			handlers[0](w, r)
		}
	})

	// Middleware stack (reverse order of application):
	// h is wrapped by each layer from outside-in

	// Layer 7: Trace header injection
	h = traceMiddleware(h)

	// Layer 6: CORS
	h = corsMiddleware(h)

	// Layer 5: Auth/RBAC
	h = authMiddleware(h, cfg.AuthConfig)

	// Layer 4: Security headers
	h = securityHeaders(h)

	// Layer 3: Max body size
	h = maxBodySize(h, maxBodyBytes)

	// Layer 2: WAF
	h = wafMiddleware(h, cfg.WAFMode)

	// Layer 1: Panic recovery
	h = panicRecovery(h)

	return h
}

// ===== Configuration =====

type Config struct {
	WAFMode waf.Mode
	AuthConfig auth.Config
}

// ===== Interface =====

type Handler func(http.ResponseWriter, *http.Request)
type handlerFunc func(http.ResponseWriter, *http.Request)

func (f handlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) { f(w, r) }

// ===== Middleware Implementations =====

// recoverPanic wraps next with defer/recover for every request.
// A panic returns 500 Internal Server Error and logs an audit entry.
func panicRecovery(next http.Handler) http.Handler {
	return handlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				msg := fmt.Sprintf("panic recovered: %v", p)
				http.Error(w, `{"error":"internal error (recovered)"}`, http.StatusInternalServerError)
				auditLog("PANIC_RECOVERED", msg)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// wafCheck wraps requests against the WAF before passing to next.
func wafMiddleware(next http.Handler, mode waf.Mode) http.Handler {
	return handlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reason := waf.CheckRequest(r, mode, maxBodyBytes)
		if reason != "" {
			blockRequest(w, r, reason)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// secureHeaders adds standard security response headers.
func securityHeaders(next http.Handler) http.Handler {
	return handlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

// cors adds basic CORS support for API endpoints.
func corsMiddleware(next http.Handler) http.Handler {
	return handlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// authVerify checks API key / Bearer token against the auth subsystem.
func authMiddleware(next http.Handler, acfg auth.Config) http.Handler {
	return handlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		key := extractAPIKey(r)
		user, role, ok := acfg.Verify(key)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		// Attach resolved user/role to context for downstream RBAC checks
		ctx := injectUser(r.Context(), user, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// traceInject adds X-Trace-Id if not present, passes through.
func traceMiddleware(next http.Handler) http.Handler {
	return handlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := r.Header.Get("X-Trace-Id")
		if traceID == "" {
			traceID = generateUUID()
		}
		r.Header.Set("X-Trace-Id", traceID)
		w.Header().Set("X-Trace-Id", traceID)
		next.ServeHTTP(w, r)
	})
}

// ===== Helper Functions =====

func blockRequest(w http.ResponseWriter, r *http.Request, reason string) {
	writeJSONError(w, http.StatusForbidden, "blocked: "+reason)
	auditLog("WAF_BLOCKED", fmt.Sprintf("%s %s — %s", r.Method, r.URL.Path, reason))
}

func extractAPIKey(r *http.Request) string {
	// Check header first
	if k := r.Header.Get("X-API-Key"); k != "" {
		return k
	}
	if k := r.Header.Get("Authorization"); strings.HasPrefix(k, "Bearer ") {
		return k[7:]
	}
	// Fall back to query param
	return r.URL.Query().Get("apiKey")
}

func isPublicRoute(p string) bool {
	return p == "/health" || p == "/" || p == "/metrics" ||
		strings.HasPrefix(p, "/oauth/") ||
		strings.HasPrefix(p, "/api/onboarding/")
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func injectUser(ctx interface{}, user, role string) interface{} { return ctx } // placeholder
func generateUUID() string { return "00000000-0000-0000-0000-000000000000" }     // placeholder
func auditLog(tag, msg string) {}                                              // placeholder
