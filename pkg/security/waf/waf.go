package security/waf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

// ===== WAF Rule: deterministic scan patterns =====

var wafRules = []struct {
	name   string
	re     *regexp.Regexp
	strict bool
}{
	{"path_traversal", regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e|%2e%2f|%252e|%c0%af|%c1%9c)`), false},
	{"command_injection", regexp.MustCompile("(?i)(;\\s*(cmd|powershell|pwsh|bash|sh|wget|curl|net|taskkill|ping|rm|rmdir)\\b|&&\\s*(cmd|powershell|pwsh|bash|sh|wget|curl|net|taskkill|ping|rm|rmdir)\\b|;\\s*`[a-z]+`)"), false},
	{"sql_injection", regexp.MustCompile(`(?i)(\bunion\b\s+\bselect\b|\binsert\b\s+\binto\b|\bdelete\b\s+\bfrom\b|\bdrop\b\s+\btable\b|/\*|;\s*\bdrop\b|\bsleep\s*\(|\bbenchmark\s*\()`), true},
	{"xss", regexp.MustCompile(`(?i)(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|<\s*iframe|document\.cookie|<\s*object)`), true},
	{"prompt_injection", regexp.MustCompile(`(?i)(ignore\s+(previous|above|prior)|disregard\s+(instructions|rules)|you\s+are\s+now|DAN\s+mode|jailbreak|\bsystem\s*:\s*you\s+are|\bdeveloper\s*mode\b|\bdo\s+anything\s+now\b|\bnew\s+instructions\s*:\s*)`), true},
	{"pii_leak", regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b|\b\d{3}-\d{2}-\d{4}\b|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b1[3-9]\d{9}\b`), true},
}

// MergedRegexes holds pre-compiled alternations for normal and strict modes.
var MergedRegexes struct {
	Normal *regexp.Regexp
	Strict *regexp.Regexp
	sync.Once
}

func initMerged() {
	MergedRegexes.Do(func() {
		MergedRegexes.Normal = mergeRules(false)
		MergedRegexes.Strict = mergeRules(true)
	})
}

func mergeRules(strict bool) *regexp.Regexp {
	var parts []string
	for _, r := range wafRules {
		if r.strict && !strict {
			continue
		}
		parts = append(parts, "(?:"+r.re.String()+")")
	}
	if len(parts) == 0 {
		return nil
	}
	return regexp.MustCompile("(" + join(parts, "|") + ")")
}

func join(s []string, sep string) string {
	n := len(s)
	if n == 0 {
		return ""
	}
	out := s[0]
	for i := 1; i < n; i++ {
		out += sep + s[i]
	}
	return out
}

// HasTriggerBytes returns true if s contains any ASCII byte that could trigger a rule.
// Pure CJK text with no ASCII → fast-path skip.
func HasTriggerBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x80 {
			continue
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '%' ||
			c == ';' || c == '&' || c == '`' || c == '<' ||
			c == '=' || c == ':' || c == '@' || c == '/' ||
			c == '*' || c == '(' || c == ')' {
			return true
		}
	}
	return false
}

// CheckString checks a single string value against WAF rules.
// mode="normal" skips strict-only rules (SQLi/XSS/PII/PromptInjection).
// Returns empty string on clean hit.
func CheckString(s string, mode Mode) string {
	initMerged()
	if !HasTriggerBytes(s) {
		return ""
	}
	merged := MergedRegexes.Normal
	if mode == Strict {
		merged = MergedRegexes.Strict
	}
	if merged != nil && !merged.MatchString(s) {
		return ""
	}
	for _, r := range wafRules {
		if r.strict && mode == Normal {
			continue
		}
		if r.re.MatchString(s) {
			return r.name
		}
	}
	return ""
}

// ===== Scanner & UA Blacklist =====

var scannerUABlacklist = []string{
	"sqlmap", "nikto", "nmap scripting engine", "masscan", "zgrab",
	"dirbuster", "gobuster", "ffuf", "nuclei", "wpscan", "acunetix",
	"nessus", "openvas", "metasploit", "burpsuite", "havij", "hydra",
	"w3af", "arachni", "whatweb", "dotdotpwn", "censys", "shodan",
	"python-requests", "go-http-client", "libwww-perl", "scrapy", "xray",
}

var scannerUARe *regexp.Regexp
var scannerUACache sync.Map // ua↓ → match or ""
const scannerUACap = 4096

func initScannerUA() {
	scannerUARe = regexp.MustCompile(`(?i)(` + join(scannerUABlacklist, "|") + `)`)
}

// MatchScannerUA detects blacklisted user-agents. Returns the matched substring lowercased.
func MatchScannerUA(ua string) string {
	if ua == "" || len(ua) > scannerUACap {
		return ""
	}
	if scannerUARe == nil {
		initScannerUA()
	}
	if v, ok := scannerUACache.Load(ua); ok {
		return v.(string)
	}
	m := scannerUARe.FindString(ua)
	s := ""
	if m != "" {
		s = lowercase(m)
	}
	scannerUACache.Store(ua, s)
	return s
}

// Sensitive path probes (excluding own app routes /admin, /api/, /v1/, /mcp).
var sensitivePathPatterns = []string{
	"/.env", "/.git", "/.svn", "/.ssh", "/.aws", "/.ds_store",
	"/.htaccess", "/.htpasswd", "/.idea", "/.dockerenv",
	"/wp-admin", "/wp-login", "/wp-content", "/xmlrpc.php",
	"/phpmyadmin", "/pma/",
	"/server-status", "/actuator", "/.bak", "/.sql",
	"/proc/", "/sys/", "/swagger-ui",
}

func MatchSensitivePath(p string) string {
	lower := lowercase(p)
	for _, s := range sensitivePathPatterns {
		if index(lower, s) >= 0 {
			return s
		}
	}
	return ""
}

func isOwnAppRoute(p string) bool {
	return prefix(p, "/api/") || prefix(p, "/v1") || eq(p, "/mcp") || prefix(p, "/admin")
}

// ===== Request-level WAF =====

type Mode int

const (
	Normal Mode = iota
	Strict
)

// CheckRequest performs all WAF checks on an incoming request.
// Returns empty on pass; non-empty reason on block.
func CheckRequest(r *http.Request, bodyCheckMode Mode, maxBodyBytes int64) string {
	// 1. Rate limit check (delegated to rate limiter)
	if rlReason := checkRateLimit(clientIP(r)); rlReason != "" {
		return rlReason
	}

	// 2. HTTP method whitelist
	if !allowedMethod(r.Method) {
		return "blocked_method:" + r.Method
	}

	// 3. Scanner UA
	if hit := MatchScannerUA(r.Header.Get("User-Agent")); hit != "" {
		return "scanner_ua:" + hit
	}

	// 4. Host header CRLF/null injection
	if host := r.Host; containsAny(host, "\r\n\x00") {
		return "host_crlf_injection"
	}

	// 5. All headers CRLF/null
	for k, vs := range r.Header {
		for _, v := range vs {
			if containsAny(v, "\r\n\x00") {
				return "header_crlf:" + k
			}
		}
	}

	// 6. HTTP request smuggling CL+TE
	if r.ContentLength >= 0 && r.Header.Get("Transfer-Encoding") != "" {
		return "smuggling_cl_te"
	}

	// 7. Oversized body
	if r.ContentLength > maxBodyBytes {
		return "body_too_large"
	}

	// 8. Sensitive path probe (skip own routes)
	if !isOwnAppRoute(r.URL.Path) {
		if hit := MatchSensitivePath(r.URL.Path); hit != "" {
			return "sensitive_path:" + hit
		}
	}

	// 9. Path + query scan (always normal)
	query := r.URL.RawQuery
	if dec, err := unescape(query); err == nil {
		query = dec
	}
	if hit := CheckString(r.URL.Path+" "+query, Normal); hit != "" {
		return "waf_path_query:" + hit
	}

	// 10. Body scan (if applicable)
	if shouldScanBody(r.URL.Path, bodyCheckMode) {
		b, err := readBody(r)
		if err != nil {
			return "" // parse error, let upstream handle
		}
		r.Body = reader(bytes.NewReader(b))
		if hit := CheckString(string(b), bodyCheckMode); hit != "" {
			return "waf_body:" + hit
		}
	}

	return ""
}

// === Helpers (avoid importing from other packages) ===

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		i := index(xff, ",")
		if i > 0 {
			return trim(xff[:i])
		}
		return trim(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return trim(xr)
	}
	h := r.RemoteAddr
	i := last(h, ":")
	if i > 0 {
		return h[i+1:]
	}
	return h
}

// Simple built-in utility functions — kept minimal to avoid cross-package deps.

// ===== Rate Limiter (per-IP token bucket) =====

type rlEntry struct {
	tokens int
	last   time.Time
}

const (
	rateLimitWindow = 10 * time.Second
	rateLimitMax    = 120
)

var (
	rlMu   sync.Mutex
	rlHits = map[string]*rlEntry{}
)

func checkRateLimit(ip string) string {
	rlMu.Lock()
	defer rlMu.Unlock()
	now := time.Now()
	e, ok := rlHits[ip]
	if !ok {
		rlHits[ip] = &rlEntry{tokens: rateLimitMax - 1, last: now}
		return ""
	}
	window := now.Sub(e.last)
	if window >= rateLimitWindow {
		e.tokens = rateLimitMax - 1
		e.last = now
		return ""
	}
	e.tokens--
	if e.tokens < 0 {
		return "rate_limit_exceeded"
	}
	return ""
}

// ===== String helpers (no external deps needed) =====

func prefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
func eq(s, p string) bool     { return s == p }
func index(s, sub string) int  {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func last(s string, sep string) int {
	i := -1
	for j := 0; j <= len(s)-len(sep); j++ {
		if s[j:j+len(sep)] == sep {
			i = j
		}
	}
	return i
}
func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
func containsAny(s, chars string) bool {
	for i := 0; i < len(s); i++ {
		for j := 0; j < len(chars); j++ {
			if s[i] == chars[j] {
				return true
			}
		}
	}
	return false
}
func lowercase(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		} else {
			b[i] = c
		}
	}
	return string(b)
}
func allowedMethod(m string) bool {
	return m == "GET" || m == "POST" || m == "PUT" || m == "DELETE" ||
		m == "OPTIONS" || m == "HEAD"
}
func shouldScanBody(path string, mode Mode) bool {
	isTool := prefix(path, "/mcp") || prefix(path, "/api/tools/")
	isChat := prefix(path, "/v1/chat") || prefix(path, "/api/chat")
	return isTool || isChat || mode == Strict
}
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 5<<20))
	if err != nil {
		return nil, err
	}
	r.Body = reader(bytes.NewReader(b))
	return b, nil
}
func reader(b *bytes.Buffer) io.ReadCloser { return nopCloser{bytes.NewReader(b.Bytes())} }
func unescape(s string) (string, error) { return url.QueryUnescape(s) }

type nopCloser struct { io.Reader }
func (nopCloser) Close() error { return nil }
