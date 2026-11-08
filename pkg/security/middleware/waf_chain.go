// Package middleware provides WAF integration helpers for the middleware chain.
package middleware

import (
	"net/http"
	"strings"
)

// WAFMiddleware wraps requests through the WAF engine before passing to handler.
func WAFMiddleware(enabled bool, mode string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				next.ServeHTTP(w, r)
				return
			}
			
			reason := checkRequest(r, mode)
			if reason != "" {
				writeJSONError(w, http.StatusForbidden, map[string]string{
					"error": "WAF blocked: " + reason,
					"reason": reason,
				})
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware adds Cross-Origin Resource Sharing headers.
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			
			allow := false
			for _, allowed := range allowedOrigins {
				if allowed == "*" || origin == allowed {
					allow = true
					break
				}
			}
			
			if allow {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
			}
			
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// RecoveryMiddleware recovers from panics in handlers.
func RecoveryMiddleware(logger interface{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if p := recover(); p != nil {
					if logger != nil {
						// Log panic via provided logger
					}
					writeJSONError(w, http.StatusInternalServerError, map[string]string{
						"error": "internal server error (recovered)",
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func checkRequest(r *http.Request, mode string) string {
	path := r.URL.Path
	
	// Check sensitive paths
	sensitivePaths := []string{".env", ".git", ".ssh", "wp-admin", "phpmyadmin"}
	lowerPath := strings.ToLower(path)
	for _, sp := range sensitivePaths {
		if strings.Contains(lowerPath, sp) {
			return "sensitive_path_probe"
		}
	}
	
	// Check scanner User-Agent
	ua := r.Header.Get("User-Agent")
	scannerUA := []string{"sqlmap", "nikto", "nmap", "burp", "scanner"}
	lowerUA := strings.ToLower(ua)
	for _, su := range scannerUA {
		if strings.Contains(lowerUA, su) {
			return "scanner_user_agent"
		}
	}
	
	return ""
}

func writeJSONError(w http.ResponseWriter, code int, m map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// Use simple encoding
}
