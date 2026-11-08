// Package gatekeeper implements the two-phase confirmation mechanism for
// high-risk tool execution. Builtin deny/confirm rules cannot be weakened
// by config — config can only tighten them.
package gatekeeper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Action is a gatekeeper verdict.
type Action int

const (
	Allow Action = iota
	Confirm
	Deny
)

func (a Action) String() string {
	switch a {
	case Allow: return "allow"
	case Confirm: return "confirm"
	default: return "deny"
	}
}

// ===== Built-in Rules =====

// sensitivePaths are paths that must never be written to by tools.
var sensitivePaths = []string{"/.ssh/", "id_rsa", "id_ed25519", "id_ecdsa",
	"credentials", "/.env", ".env.", "/.git/config", "authorized_keys",
	"known_hosts", ".aws/credentials", ".kube/config", ".netrc"}

// protectedConfigPrefixes are security-critical config paths.
var protectedConfigPrefixes = []string{"security.", "oauth.", "tenants.", "gatekeeper.", "audit."}

// builtin returns the built-in action for a given tool + arguments.
// Deny > Confirm > Allow hierarchy: strongest wins.
func builtin(tool string, args map[string]interface{}) (Action, string) {
	switch tool {
	case "tars_config_set":
		if path, ok := args["path"].(string); ok && inProtectedConfig(path) {
			return Deny, "security-critical config path not modifiable via tool: "+path
		}
		return Confirm, "config change requires confirmation"

	case "tars_model_start", "tars_model_stop", "tars_model_download":
		return Confirm, "high-impact model action requires confirmation: "+tool

	case "tars_file_write":
		path, _ := args["path"].(string)
		if inSensitivePath(path) {
			return Deny, "sensitive path (credentials/secrets) denied: "+path
		}
		if content, ok := args["content"].(string); ok && len(content) > 1<<20 {
			return Confirm, fmt.Sprintf("single write %d bytes exceeds 1MB protection threshold", len(content))
		}
		return Allow, ""
	default:
		return Allow, ""
	}
}

// ===== External Rules =====

// Rule defines a user-configurable gatekeeper rule. Pattern supports trailing * wildcard.
type Rule struct {
	Tools       []string `json:"tools"`
	Action      string   `json:"action"` // "deny", "confirm", "allow"
	Description string   `json:"description"`
}

// Config holds the gatekeeper configuration section from config.json.
type Config struct {
	Enabled bool     `json:"enabled"` // default true
	Rules   []Rule   `json:"rules"`   // external rules (can only tighten, never loosen)
}

// Decide performs full decision: builtin + external rules.
// External rules can only tighten (deny/confirm on allow → escalate);
// they cannot loosen a builtin deny/confirm.
func Decide(tool string, args map[string]interface{}, extRules []Rule) (Action, string) {
	v, why := builtin(tool, args)
	for _, r := range extRules {
		if !matchTool(r.Tools, tool) {
			continue
		}
		switch r.Action {
		case "deny":
			if v != Deny {
				v = Deny
				why = "gatekeeper rule deny: " + r.Description
			}
		case "confirm":
			if v == Allow {
				v = Confirm
				why = "gatekeeper rule requires confirm: " + r.Description
			}
		case "allow":
			if v == Deny || v == Confirm {
				auditLog("GATEKEEPER_POLICY_OVERRIDE",
					fmt.Sprintf("ext rule tried to loosen %s→allow (denied, maintained %s)", tool, v))
			}
		}
	}
	return v, why
}

// ===== Two-Phase Confirm Tokens =====

type pending struct {
	User     string    `json:"user"`
	Tool     string    `json:"tool"`
	ArgsHash string    `json:"args_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

var (
	gkMu      sync.Mutex
	gkPending = map[string]pending{}
	gkRateWin = map[string][]time.Time{} // user → confirm-trigger timestamps
)

const (
	gkConfirmTTL       = 60 * time.Second
	gkMaxPending       = 10
	gkMaxConfirmPerMin = 20
)

// IssueToken creates a one-time, single-use confirmation token valid for TTL.
// The token binds user + tool + argument hash — tampering with any parameter invalidates it.
func IssueToken(user, tool string, args map[string]interface{}) (string, time.Time, error) {
	gkMu.Lock()
	defer gkMu.Unlock()
	now := time.Now()
	// Sweep expired entries
	for k, p := range gkPending {
		if now.After(p.ExpiresAt) {
			delete(gkPending, k)
		}
	}
	// Check pending limit
	count := pendingCountLocked(user)
	if count >= gkMaxPending {
		return "", time.Time{}, fmt.Errorf("too many pending confirmations (max %d)", gkMaxPending)
	}
	tok := newToken()
	exp := now.Add(gkConfirmTTL)
	bound := boundArgsHash(tool, args)
	gkPending[tok] = pending{User: user, Tool: tool, ArgsHash: bound, ExpiresAt: exp}
	return tok, exp, nil
}

// ConsumeToken validates and consumes a confirmation token. Single-use; verifies
// user + tool + arg binding to prevent replay attacks.
func ConsumeToken(token, user, tool string, args map[string]interface{}) error {
	gkMu.Lock()
	defer gkMu.Unlock()
	p, ok := gkPending[token]
	if !ok {
		return fmt.Errorf("confirmation token not found or already consumed")
	}
	if time.Now().After(p.ExpiresAt) {
		delete(gkPending, token)
		return fmt.Errorf("confirmation token expired")
	}
	bound := boundArgsHash(tool, args)
	if p.ArgsHash != bound {
		auditLog("GATEKEEPER_TOKEN_MISMATCH",
			fmt.Sprintf("user=%s tool=%s token=%s arg hash mismatch", user, tool, token[:8]))
		return fmt.Errorf("argument tampering detected")
	}
	if p.User != user {
		auditLog("GATEKEEPER_TOKEN_USER_MISMATCH",
			fmt.Sprintf("token issued for %s, consumed by %s", p.User, user))
		return fmt.Errorf("confirmation token user mismatch")
	}
	delete(gkPending, token)
	auditLog("GATEKEEPER_CONFIRMED",
		fmt.Sprintf("user=%s tool=%s confirmed", user, tool))
	return nil
}

// RateExceeded checks per-user confirm frequency (20/min max).
func RateExceeded(user string) bool {
	gkMu.Lock()
	defer gkMu.Unlock()
	now := time.Now()
	win := gkRateWin[user][:0]
	for _, t := range gkRateWin[user] {
		if now.Sub(t) < time.Minute {
			win = append(win, t)
		}
	}
	if len(win) >= gkMaxConfirmPerMin {
		gkRateWin[user] = win
		return true
	}
	gkRateWin[user] = append(win, now)
	return false
}

// ===== Helpers =====

func matchTool(patterns []string, tool string) bool {
	for _, pat := range patterns {
		if pat == "*" {
			return true
		}
		if len(pat) > 1 && pat[len(pat)-1] == '*' {
			return len(tool) >= len(pat)-1 && tool[:len(pat)-1] == pat[:len(pat)-1]
		}
		if pat == tool {
			return true
		}
	}
	return false
}

func inSensitivePath(p string) bool {
	lp := lowercase(p)
	for _, s := range sensitivePaths {
		if contains(lp, s) {
			return true
		}
	}
	return false
}

func inProtectedConfig(p string) bool {
	for _, pre := range protectedConfigPrefixes {
		if startsWith(p, pre) {
			return true
		}
	}
	return false
}

func boundArgsHash(tool string, args map[string]interface{}) string {
	bound := make(map[string]interface{}, len(args))
	for k, v := range args {
		if k == "confirm_token" || k == "_tsgIdentity" {
			continue
		}
		bound[k] = v
	}
	b, _ := json.Marshal(bound)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "gk_" + hex.EncodeToString(b)
}

func pendingCountLocked(user string) int {
	n := 0
	now := time.Now()
	for _, p := range gkPending {
		if now.After(p.ExpiresAt) {
			delete(gkPending, p.User)
			continue
		}
		if p.User == user {
			n++
		}
	}
	return n
}

func auditLog(tag, msg string) {}

// === Minimal string helpers ===
func lowercase(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}
func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
