// Package module provides a feature-flag framework with dependency topology.
// security-core is always loaded; all other modules have independent on/off switches.
package module

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Module defines a single feature module.
type Module struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"` // core | models | tools | network | ops | security
	Default     bool     `json:"default"`
	Deps        []string `json:"deps"`     // dependent module IDs
	HasWorker   bool     `json:"has_worker"`
}

// ===== Registered Modules =====

var registry = []Module{
	{ID: "chatApi", Name: "Chat API", Description: "Chat completion and OpenAI-compatible /v1 layer", Category: "core", Default: true},
	{ID: "localModels", Name: "Local Models", Description: "Local GGUF model management, LM Studio/Ollama backends", Category: "models", Default: true},
	{ID: "modelDownload", Name: "Model Download", Description: "Model download manager with progress tracking", Category: "models", Default: true, Deps: []string{"localModels"}},
	{ID: "cloudModels", Name: "Cloud Models", Description: "Cloud model routing (OpenAI/DeepSeek/custom)", Category: "models", Default: true},
	{ID: "webSearch", Name: "Web Search", Description: "Built-in Bing RSS and Serper search", Category: "tools", Default: true},
	{ID: "webFetch", Name: "Web Fetch", Description: "URL fetch to text conversion", Category: "tools", Default: true},
	{ID: "openapiTools", Name: "OpenAPI Tools", Description: "OpenAPI document parsing for tool generation", Category: "tools", Default: true, Deps: []string{"webFetch"}},
	{ID: "mcpExternal", Name: "External MCP", Description: "External MCP stdio server bridge", Category: "tools", Default: true},
	{ID: "builtinTools", Name: "Builtin Tools", Description: "Built-in tool registry at /api/tools/", Category: "tools", Default: true},
	{ID: "customTools", Name: "Custom Tools", Description: "User-defined HTTP forwarder tools", Category: "tools", Default: false, Deps: []string{"builtinTools"}},
	{ID: "memory", Name: "Memory", Description: "Persistent memory store", Category: "core", Default: true},
	{ID: "contextGov", Name: "Context Governance", Description: "Shared KV memory, shared info, context budget injection", Category: "core", Default: true, Deps: []string{"builtinTools"}},
	{ID: "semanticGuard", Name: "Semantic Guard", Description: "Static rules + grey-zone engine, fail-close, AI-only-tighten", Category: "security", Default: true},
	{ID: "smartRouter", Name: "Smart Router", Description: "Two-stage: static rules + ε-greedy bandit for auto-routing", Category: "ops", Default: true},
	{ID: "resourceGuardian", Name: "Resource Guardian", Description: "GOMEMLIMIT soft limit + L0-L3 tiered response + eco mode", Category: "ops", Default: true},
	{ID: "sidecarHub", Name: "Sidecar Hub", Description: "Ex-module host: manifest + SHA-256 pinning + lifecycle management", Category: "tools", Default: true},
	{ID: "persona", Name: "Persona System", Description: "Career presets: student/writer/developer/researcher with auto-config", Category: "core", Default: true},
	{ID: "observability", Name: "Observability", Description: "Prometheus metrics, trace/span timeline, per-request stats", Category: "ops", Default: true},
}

// Security module description — locked, no toggle.
var securityDesc = Module{
	ID: "security-core", Name: "Security Core",
	Description: "WAF / Auth / RBAC / Rate Limit / Audit / PII Masking (forced load, cannot disable)",
	Category: "security", Default: true,
}

// ===== Runtime State =====

var (
	mu       sync.RWMutex
	states   = map[string]bool{} // current state per module ID
	configFn string              // config.json path (for saveConfig)
)

// SetConfigPath sets the config file path for persistence.
func SetConfigPath(path string) {
	configFn = path
}

// InitDefaults initializes states from registry defaults.
func InitDefaults() {
	mu.Lock()
	defer mu.Unlock()
	states = make(map[string]bool, len(registry))
	for _, m := range registry {
		states[m.ID] = m.Default
	}
	states["security-core"] = true // always on
}

// Enabled reports whether module id is currently enabled.
func Enabled(id string) bool {
	if id == "security-core" {
		return true
	}
	mu.RLock()
	v, ok := states[id]
	mu.RUnlock()
	if ok {
		return v
	}
	for _, m := range registry {
		if m.ID == id {
			return m.Default
		}
	}
	return false
}

// Apply reads module states from a JSON map and applies dependency topology closure.
// Iterative fixpoint up to N rounds. Audit logs applied during closure.
func Apply(modules map[string]bool) error {
	mu.Lock()
	defer mu.Unlock()

	// Step 1: merge config with registry
	next := make(map[string]bool, len(registry))
	for _, m := range registry {
		if v, ok := modules[m.ID]; ok {
			next[m.ID] = v
		} else {
			next[m.ID] = m.Default
		}
	}
	next["security-core"] = true // lock

	// Step 2: dependency closure until stable
	for iter := 0; iter <= len(registry); iter++ {
		changed := false
		for _, m := range registry {
			if next[m.ID] {
				for _, d := range m.Deps {
					if !next[d] {
						next[d] = true
						auditLog("MODULE_AUTO_ENABLE",
							fmt.Sprintf("%s needs %s → auto-enabled", m.ID, d))
						changed = true
					}
				}
			} else {
				for _, o := range registry {
					if next[o.ID] && contains(o.Deps, m.ID) {
						next[o.ID] = false
						auditLog("MODULE_AUTO_DISABLE",
							fmt.Sprintf("%s depends on %s which was disabled → also disabled", o.ID, m.ID))
						changed = true
					}
				}
			}
		}
		if !changed {
			break
		}
	}

	states = next
	saveModulesConfig(next)
	return nil
}

// Toggle enables or disables a module. Returns error if invalid or violates deps.
func Toggle(id string, enable bool) error {
	mu.Lock()
	defer mu.Unlock()

	known := false
	for _, m := range registry {
		if m.ID == id {
			known = true
			break
		}
	}
	if !known && id != "security-core" {
		return fmt.Errorf("unknown module: %s", id)
	}
	if id == "security-core" {
		return fmt.Errorf("security-core is forced, cannot toggle")
	}

	next := make(map[string]bool, len(states))
	for k, v := range states {
		next[k] = v
	}
	next[id] = enable

	if enable {
		// Auto-enable dependencies
		for _, m := range registry {
			if next[m.ID] {
				for _, d := range m.Deps {
					if !next[d] {
						next[d] = true
						auditLog("MODULE_AUTO_ENABLE", fmt.Sprintf("%s needs %s → auto-enabled", m.ID, d))
					}
				}
			}
		}
	} else {
		// Check that no other enabled module depends on this one
		for _, m := range registry {
			if next[m.ID] && contains(m.Deps, id) {
				return fmt.Errorf("module %s depends on %s, disable %s first", m.ID, id, m.ID)
			}
		}
	}

	states = next
	saveModulesConfig(next)
	return nil
}

// List returns all module definitions with their current runtime state.
func List() []map[string]interface{} {
	result := []map[string]interface{}{{
		"id": "security-core", "name": securityDesc.Name,
		"description": securityDesc.Description,
		"category": "security", "enabled": true, "locked": true,
	}}
	for _, m := range registry {
		result = append(result, map[string]interface{}{
			"id": m.ID, "name": m.Name, "description": m.Description,
			"category": m.Category, "enabled": Enabled(m.ID),
			"locked": false, "deps": m.Deps, "default": m.Default,
			"has_worker": m.HasWorker,
		})
	}
	return result
}

// Helper functions.
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func auditLog(tag, msg string) {}

// Save modules states to config.json's modules field (minimal implementation).
func saveModulesConfig(mods map[string]bool) {
	if configFn == "" {
		return
	}
	b, err := os.ReadFile(configFn)
	if err != nil {
		return
	}
	var cfg map[string]interface{}
	if json.Unmarshal(b, &cfg) != nil {
		return
	}
	cfg["modules"] = mods
	out, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(configFn+".tmp", out, 0o644)
	os.Rename(configFn+".tmp", configFn)
}
