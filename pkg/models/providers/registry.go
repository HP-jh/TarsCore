// Package providers manages the model provider registry.
// Each provider is a backend (OpenAI, Anthropic, Ollama, local GGUF, etc.)
// with connection params, health probes, and circuit-breaker integration.
package providers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Provider defines an AI backend endpoint.
type Provider struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	BaseURL  string `json:"base_url"`
	Type     string `json:"type"` // openai | anthropic | ollama | lmstudio | local_gguf | custom
	APIKey   string `json:"api_key,omitempty"`
	Models   []string `json:"models,omitempty"`
	Active   bool `json:"active"`
	HasKey   bool `json:"has_key"` // derived: APIKey != ""
}

// Registry holds all configured providers and their metadata.
type Registry struct {
	mu    sync.RWMutex
	providers map[string]*Provider
	builtin int // number of built-in provider templates
}

// New creates a registry from optional built-in JSON files and config overrides.
func New(builtinJSON ...string) *Registry {
	r := &Registry{
		providers: make(map[string]*Provider),
	}
	// Load built-in provider templates from JSON files
	for _, fn := range builtinJSON {
		loadBuiltIn(r, fn)
	}
	return r
}

// Add registers a new provider (usually from config.json cloud.* custom).
func (r *Registry) Add(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p.HasKey = p.APIKey != ""
	r.providers[p.ID] = &p
}

// Get returns a provider by ID. Returns nil if not found.
func (r *Registry) Get(id string) *Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.providers[id]
}

// List returns all active providers.
func (r *Registry) List() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		if p.Active {
			cp := *p
			cp.APIKey = "[REDACTED]" // never echo keys via API
			out = append(out, cp)
		}
	}
	return out
}

// Count returns total registered providers.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}

// HasKeyCount returns number of providers with valid API keys.
func (r *Registry) HasKeyCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, p := range r.providers {
		if p.HasKey {
			n++
		}
	}
	return n
}

// Remove deletes a provider by ID.
func (r *Registry) Remove(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[id]; !ok {
		return false
	}
	delete(r.providers, id)
	return true
}

// SavePersistents writes the registry state to a JSON file for cross-process sharing.
func (r *Registry) Save(path string) error {
	r.mu.RLock()
	data := make(map[string]Provider)
	for k, v := range r.providers {
		data[k] = *v
	}
	r.mu.RUnlock()
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	return os.WriteFile(path, b, 0o644)
}

// LoadPersistent reads previously saved registry from disk.
func (r *Registry) Load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var data map[string]Provider
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	r.mu.Lock()
	for id, p := range data {
		p.HasKey = p.APIKey != ""
		r.providers[id] = &p
	}
	r.mu.Unlock()
	return nil
}

func loadBuiltIn(r *Registry, path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var plist []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		BaseURL string `json:"base_url"`
		Type    string `json:"type"`
		Models  []string `json:"models,omitempty"`
	}
	if err := json.Unmarshal(b, &plist); err != nil {
		return
	}
	r.mu.Lock()
	for _, p := range plist {
		r.providers[p.ID] = &Provider{
			ID: p.ID, Name: p.Name, BaseURL: p.BaseURL,
			Type: p.Type, Active: true, HasKey: false, Models: p.Models,
		}
	}
	r.builtin += len(plist)
	r.mu.Unlock()
}
