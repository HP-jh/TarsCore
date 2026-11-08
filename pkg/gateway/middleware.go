// Package gateway provides additional middleware functions for the HTTP server.
package gateway

import (
	"net/http"
	"strings"
)

// SecurityHeadersMiddleware adds standard security headers.
func SecurityHeadersMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware implements basic rate limiting.
func RateLimitMiddleware(maxRequestsPerMinute int) func(http.Handler) http.Handler {
	type clientInfo struct {
		requests int
		windowStart int64
	}
	
	clientMap := make(map[string]*clientInfo)
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r)
			
			now := r.Context().Value("now").(int64) // Would be set by a previous middleware
			
			info, exists := clientMap[ip]
			if !exists {
				info = &clientInfo{windowStart: now}
				clientMap[ip] = info
			}
			
			if now - info.windowStart >= 60 {
				info.requests = 0
				info.windowStart = now
			}
			
			info.requests++
			
			if info.requests > maxRequestsPerMinute {
				writeJSONError(w, http.StatusTooManyRequests, map[string]string{
					"error": "rate limit exceeded",
				})
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
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

func writeJSONError(w http.ResponseWriter, code int, m map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
}
