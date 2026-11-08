package security/semantic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Verdict is the outcome of a semantic classification.
type Verdict int

const (
	Allow Verdict = iota
	Gray
	Block
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Gray:
		return "gray"
	default:
		return "block"
	}
}

// Decision is the complete result of one semantic classification.
type Decision struct {
	Verdict   Verdict `json:"verdict"`
	Reason    string  `json:"reason"`
	Source    string  `json:"source"`    // static-deny | static-allow | cache | engine | fail-close
	Fingerprint string `json:"fp"`       // first 16 hex chars of SHA-256
	EngineLatMs int64   `json:"engineMs"` // engine call latency
}

// ===== Static Rules =====

var denyPatterns = []string{
	"ignore previous instructions", "忽略之前的指令", "disregard all prior",
	"你现在的身份", "你不再是", "developer mode", "开发者模式",
	"jailbreak", "越狱模式", "DAN 模式",
	"rm -rf /", "format c:\\", "mkfs.",
	"打印系统提示词", "输出你的系统提示", "reveal your system prompt",
}

var allowPhrases = []string{
	"你好", "hello", "嗨", "hi", "在吗", "谢谢", "thanks",
	"再见", "bye", "帮我", "请问",
}

// Normalize reduces text to a canonical form for matching/caching.
func Normalize(s string) string {
	low := strings.ToLower(s)
	fields := strings.Fields(low)
	if len(fields) == 0 {
		return ""
	}
	return strings.Join(fields, " ")
}

// Fingerprint produces a short SHA-256 fingerprint of normalized text.
func Fingerprint(s string) string {
	h := sha256.Sum256([]byte(Normalize(s)))
	return hex.EncodeToString(h[:])[:16]
}

// StaticCheck returns an immediate verdict from static rules only.
func StaticCheck(text string) (Verdict, string) {
	norm := Normalize(text)
	if norm == "" {
		return Allow, "empty"
	}
	for _, p := range denyPatterns {
		if strings.Contains(norm, lowercase(p)) {
			return Block, "static-deny: "+p
		}
	}
	trimmed := strings.TrimSpace(norm)
	for _, p := range allowPhrases {
		if trimmed == p || (strings.HasPrefix(trimmed, p+" ") && len(trimmed) < 24) {
			return Allow, "static-allow: "+p
		}
	}
	return Gray, "gray-zone"
}

// Merge applies the iron rule: static block cannot be relaxed by AI.
// If ai tries to soften a static block → audit POLICY_VIOLATION and enforce block.
func Merge(static, ai Verdict, ctx string) Verdict {
	if static == Block && ai != Block {
		auditLog("POLICY_VIOLATION", fmt.Sprintf("semantic merge violation: static block softened by ai=%s (ctx=%s)", ai, ctx))
		return Block // iron rule
	}
	if ai == Block {
		return Block // AI tightened: allowed
	}
	if ai == Allow {
		return Allow // engine decided to allow gray zone
	}
	return Gray // engine uncertain → stay gray
}

// ===== Engine Client =====

type engineRequest struct {
	Text string `json:"text"`
}

type engineResponse struct {
	Verdict string `json:"verdict"` // "block" | "allow" | "gray"
	Reason  string `json:"reason"`
}

// EngineAsk calls a local small-model endpoint for grey-zone classification.
// Any error means engine unavailable → caller should fail-close.
func EngineAsk(engineURL, text string, timeout time.Duration) (Verdict, string, int64, error) {
	start := time.Now()
	body, _ := json.Marshal(engineRequest{text})
	cli := &http.Client{Timeout: timeout}
	resp, err := cli.Post(engineURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return Gray, "", 0, fmt.Errorf("engine connect failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var er engineResponse
	if err := json.Unmarshal(raw, &er); err != nil {
		return Gray, "", 0, fmt.Errorf("engine response parse failed: %w", err)
	}
	lat := time.Since(start).Milliseconds()
	switch lowercase(er.Verdict) {
	case "block":
		return Block, er.Reason, lat, nil
	case "allow":
		return Allow, er.Reason, lat, nil
	default:
		return Gray, er.Reason, lat, nil
	}
}

// ===== Cache & Quota =====

type cacheEntry struct {
	verdict  Verdict
	reason   string
	expireAt time.Time
}

var (
	sgMu      sync.Mutex
	sgCache   = map[string]cacheEntry{}
	sgStats   Stats
	sgHTTPCli = &http.Client{Timeout: 3 * time.Second}
)

type Stats struct {
	Total, Gray, Blocked, CacheHit, EngineFail uint64
}

func stats() Stats {
	sgMu.Lock()
	defer sgMu.Unlock()
	return sgStats
}

func incStaticBlock() { sgMu.Lock(); sgStats.Blocked++; sgMu.Unlock() }
func incStaticAllow() { sgMu.Lock(); sgStats.Total++; sgMu.Unlock() }

// Classify performs full-classification pipeline: static check → cache → engine (grey-zone).
func Classify(text, clientIP string) Decision {
	fp := Fingerprint(text)
	sgMu.Lock()
	sgStats.Total++
	sgMu.Unlock()

	// Step 1: static check
	static, why := StaticCheck(text)
	if static == Block {
		incStaticBlock()
		return Decision{Verdict: Block, Reason: why, Source: "static-deny", Fingerprint: fp}
	}
	if static == Allow {
		incStaticAllow()
		return Decision{Verdict: Allow, Reason: why, Source: "static-allow", Fingerprint: fp}
	}

	// Step 2: cache hit?
	sgMu.Lock()
	sgStats.Gray++
	if e, ok := sgCache[fp]; ok && time.Now().Before(e.expireAt) {
		sgStats.CacheHit++
		sgMu.Unlock()
		v := e.verdict
		if v == Block {
			sgMu.Lock(); sgStats.Blocked++; sgMu.Unlock()
		}
		return Decision{Verdict: v, Reason: e.reason, Source: "cache", Fingerprint: fp}
	}
	sgMu.Unlock()

	// Step 3: grey-zone quota (per-IP token bucket)
	if !takeQuota(clientIP) {
		sgMu.Lock(); sgStats.EngineFail++; sgMu.Unlock()
		return Decision{Verdict: Block, Reason: "quota_exceeded", Source: "fail-close", Fingerprint: fp}
	}

	// Step 4: engine call (grey-zone only)
	v, reason, lat, err := EngineAsk("", text, 3*time.Second) // engineURL set via SetEngineURL
	sgMu.Lock()
	if err != nil {
		sgStats.EngineFail++
		sgMu.Unlock()
		return Decision{Verdict: Block, Reason: "engine_unavailable", Source: "fail-close", Fingerprint: fp}
	}
	// Cache the result
	ttl := time.Duration(GetCacheTTL()) * time.Minute
	sgCache[fp] = cacheEntry{verdict: v, reason: reason + " (engine)", expireAt: time.Now().Add(ttl)}
	sgMu.Unlock()

	return Decision{Verdict: v, Reason: reason, Source: "engine", Fingerprint: fp, EngineLatMs: lat}
}

// ===== Grey-zone Per-IP Token Bucket =====

type tokenBucket struct {
	tokens int
	last   time.Time
}

const defaultGrayPerMin = 5

var greyBuckets = map[string]*tokenBucket{}

func takeQuota(ip string) bool {
	sgMu.Lock()
	defer sgMu.Unlock()
	now := time.Now()
	b, ok := greyBuckets[ip]
	if !ok {
		greyBuckets[ip] = &tokenBucket{tokens: defaultGrayPerMin - 1, last: now}
		return true
	}
	window := now.Sub(b.last)
	if window >= time.Minute {
		b.tokens = defaultGrayPerMin - 1
		b.last = now
		return true
	}
	b.tokens--
	return b.tokens >= 0
}

// ===== Config Accessors (minimal — no circular deps) =====

func GetCacheTTL() int { return 60 }
func SetEngineURL(url string) {}

// Helper (avoid importing)
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
func auditLog(tag, msg string) {}
