// Package models manages model lifecycle: detection, startup, shutdown, and chat routing.
package models

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ===== Types =====

// Model represents a single AI model instance.
type Model struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"` // local | ollama | lmstudio | openai | deepseek | custom
	Backend  string   `json:"backend"` // provider backend identifier
	BaseURL  string   `json:"base_url,omitempty"`
	Status   string   `json:"status"` // idle | loading | ready | error
	Port     int      `json:"port,omitempty"`
	GGUFPath string   `json:"gguf_path,omitempty"`
	SizeGB   float64  `json:"size_gb,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResult struct {
	Content string `json:"content"`
	Backend string `json:"backend"`
}

// Manager owns the entire model registry and lifecycle.
type Manager struct {
	mu             sync.RWMutex
	models         map[string]*Model
	localProcesses map[string]*processState
	llamaDir       string // path to llama-server binary
	modelDir       string // path to GGUF model files
	maxBodyBytes   int64
}

type processState struct {
	cmd      *exec.Cmd
	proc     *os.Process
	port     int
	output   bytes.Buffer
	started  time.Time
	ggufPath string
}

var defaultManager *Manager

func init() {
	defaultManager = New("/home", "/usr/local/bin")
}

// New creates a new model manager.
// modelDir is where GGUF files live; llamaDir is where llama-server binaries are found.
func New(modelDir, llamaDir string) *Manager {
	return &Manager{
		models:         make(map[string]*Model),
		localProcesses: make(map[string]*processState),
		llamaDir:       llamaDir,
		modelDir:       modelDir,
		maxBodyBytes:   5 << 20, // 5 MB
	}
}

// DiscoverLocal scans for known local inference backends.
func (m *Manager) DiscoverLocal() []Model {
	var models []Model

	// Ollama auto-discovery
	if o := m.detectOllama(); o != nil {
		for _, id := range o.Models {
			models = append(models, Model{
				ID: id, Name: id, Type: "ollama", Backend: "ollama",
				BaseURL: "http://127.0.0.1:11434", Status: "ready", Port: 11434,
			})
		}
	}

	// LM Studio auto-discovery
	if l := m.detectLMStudio(); l != nil {
		for _, id := range l.Models {
			models = append(models, Model{
				ID: id, Name: id, Type: "lmstudio", Backend: "lmstudio",
				BaseURL: "http://127.0.0.1:1234", Status: "ready", Port: 1234,
			})
		}
	}

	// Scan GGUF files in model directory
	if ggufs := m.scanGGUF(m.modelDir); len(ggufs) > 0 {
		for _, g := range ggufs {
			id := strings.TrimSuffix(filepath.Base(g), filepath.Ext(g))
			sizeGB := fileSizeGB(g)
			models = append(models, Model{
				ID: id, Name: id, Type: "local_gguf", Backend: "llama",
				Status: "idle", GGUFPath: g, SizeGB: sizeGB,
			})
		}
	}

	return models
}

// StartLocal launches a local GGUF model via llama-server.
func (m *Manager) StartLocal(modelID, ggufPath string, port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ps, exists := m.localProcesses[modelID]; exists && ps.proc != nil {
		return fmt.Errorf("model %s already running on port %d", modelID, ps.port)
	}

	// Find llama-server binary
	bin := m.findLlamaServer()
	if bin == "" {
		return fmt.Errorf("llama-server binary not found in %s", m.llamaDir)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin,
		"--model", ggufPath,
		"--host", "127.0.0.1",
		"--port", fmt.Sprint(port),
		"--ctx-size", "4096",
		"--threads", fmt.Sprint(os.NumCPU()),
	)

	ps := &processState{cmd: cmd, port: port, started: time.Now(), ggufPath: ggufPath}
	cmd.Stdout = &ps.output
	cmd.Stderr = &ps.output

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start llama-server: %w", err)
	}
	ps.proc = cmd.Process

	m.localProcesses[modelID] = ps

	// Wait for server to be ready (poll /health endpoint)
	readyCh := make(chan error, 1)
	go func() {
		for i := 0; i < 30; i++ {
			time.Sleep(1 * time.Second)
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", port))
			if err == nil {
				resp.Body.Close()
				readyCh <- nil
				return
			}
		}
		readyCh <- fmt.Errorf("timeout waiting for llama-server on port %d", port)
	}()

	select {
	case err := <-readyCh:
		if err != nil {
			ps.proc.Kill()
			delete(m.localProcesses, modelID)
			return fmt.Errorf("server did not become ready: %w", err)
		}
		return nil
	case <-time.After(35 * time.Second):
		ps.proc.Kill()
		delete(m.localProcesses, modelID)
		return fmt.Errorf("server failed to start within timeout")
	}
}

// StopLocal stops a running local model.
func (m *Manager) StopLocal(modelID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ps, ok := m.localProcesses[modelID]
	if !ok || ps.proc == nil {
		return fmt.Errorf("model %s not running", modelID)
	}

	if err := ps.proc.Kill(); err != nil {
		return fmt.Errorf("kill failed: %w", err)
	}
	delete(m.localProcesses, modelID)
	return nil
}

// Chat routes a chat request to the appropriate backend.
// If modelID starts with a prefix (e.g. "ollama/", "lmstudio/"), uses that backend.
// Otherwise auto-selects: prefer local, fall back to cloud.
func (m *Manager) Chat(modelID string, messages []Message, maxTokens int) (*ChatResult, error) {
	if modelID == "" || modelID == "auto" {
		// Try local first
		if active := m.getLocalBackend(); active != "" {
			result, err := m.chatToBackend(active, messages, maxTokens)
			if err == nil {
				return result, nil
			}
		}
		// Fall back to cloud
		if cloud := m.getCloudBackend(); cloud != "" {
			return m.chatToCloud(cloud, messages, maxTokens)
		}
		return nil, fmt.Errorf("no available backend (local or cloud)")
	}

	prefix, target := splitBackendPrefix(modelID)
	switch prefix {
	case "ollama":
		return m.chatToOllama(target, messages, maxTokens)
	case "lmstudio":
		return m.chatToLMStudio(target, messages, maxTokens)
	case "llama":
		return m.chatToLocal(target, messages, maxTokens)
	case "openai":
		return m.chatToOpenAI(target, messages, maxTokens)
	case "deepseek":
		return m.chatToDeepSeek(target, messages, maxTokens)
	default:
		// Unknown prefix — try as local model ID
		return m.chatToLocal(modelID, messages, maxTokens)
	}
}

// GetRunning returns all currently running local models.
func (m *Manager) GetRunning() []Model {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var running []Model
	for id, ps := range m.localProcesses {
		if ps.proc != nil {
			running = append(running, Model{
				ID: id, Name: id, Type: "local_gguf", Backend: "llama",
				Status: "running", Port: ps.port, GGUFPath: ps.ggufPath,
			})
		}
	}
	return running
}

// ListAll returns every discovered model (running + discoverable).
func (m *Manager) ListAll() []Model {
	discovered := m.DiscoverLocal()
	running := m.GetRunning()

	seen := make(map[string]bool)
	for _, r := range running {
		seen[r.ID] = true
	}

	result := append([]Model{}, running...)
	for _, d := range discovered {
		if !seen[d.ID] {
			result = append(result, d)
		}
	}
	return result
}

// ===== Backend Chat Implementations =====

func (m *Manager) chatToBackend(backend string, messages []Message, maxTokens int) (*ChatResult, error) {
	switch {
	case strings.HasPrefix(backend, "http"):
		return m.chatViaHTTP(backend, messages, maxTokens)
	default:
		return m.chatToLocal(backend, messages, maxTokens)
	}
}

func (m *Manager) chatToLocal(modelID string, messages []Message, maxTokens int) (*ChatResult, error) {
	m.mu.RLock()
	ps, ok := m.localProcesses[modelID]
	m.mu.RUnlock()

	if !ok || ps.proc == nil {
		return nil, fmt.Errorf("local model %s not running", modelID)
	}

	payload := map[string]interface{}{
		"prompt":      formatPrompt(messages),
		"max_tokens":  maxTokens,
		"temperature": 0.7,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(
		fmt.Sprintf("http://127.0.0.1:%d/completion", ps.port),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("chat failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, m.maxBodyBytes))
	var result struct {
		Text string `json:"text"`
	}
	json.Unmarshal(raw, &result)

	if result.Text == "" {
		return nil, fmt.Errorf("empty response from llama-server")
	}
	return &ChatResult{Content: result.Text, Backend: "llama/" + modelID}, nil
}

func (m *Manager) chatToOllama(modelID string, messages []Message, maxTokens int) (*ChatResult, error) {
	payload := map[string]interface{}{
		"model":      modelID,
		"messages":   toJSON(messages),
		"max_tokens": maxTokens,
		"stream":     false,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post("http://127.0.0.1:11434/api/chat", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ollama chat failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, m.maxBodyBytes))
	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	json.Unmarshal(raw, &result)

	return &ChatResult{Content: result.Message.Content, Backend: "ollama/" + modelID}, nil
}

func (m *Manager) chatToLMStudio(modelID string, messages []Message, maxTokens int) (*ChatResult, error) {
	return m.chatViaHTTP("http://127.0.0.1:1234", messages, maxTokens)
}

func (m *Manager) chatToOpenAI(endpoint, messages []Message, maxTokens int) (*ChatResult, error) {
	provider := findProvider("openai")
	if provider == nil || provider.APIKey == "" {
		return nil, fmt.Errorf("OpenAI API key not configured")
	}

	payload := map[string]interface{}{
		"model":      endpoint,
		"messages":   toJSON(messages),
		"max_tokens": maxTokens,
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", provider.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+provider.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("OpenAI chat failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, m.maxBodyBytes))
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.Unmarshal(raw, &result)

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("empty OpenAI response")
	}
	return &ChatResult{Content: result.Choices[0].Message.Content, Backend: "openai/" + endpoint}, nil
}

func (m *Manager) chatToDeepSeek(endpoint, messages []Message, maxTokens int) (*ChatResult, error) {
	return m.chatToOpenAI("https://api.deepseek.com/v1"+endpoint, messages, maxTokens)
}

func (m *Manager) chatViaHTTP(baseURL string, messages []Message, maxTokens int) (*ChatResult, error) {
	payload := map[string]interface{}{
		"messages":   toJSON(messages),
		"max_tokens": maxTokens,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(baseURL+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("HTTP chat failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, m.maxBodyBytes))
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	json.Unmarshal(raw, &result)

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("empty HTTP response")
	}
	return &ChatResult{Content: result.Choices[0].Message.Content, Backend: baseURL}, nil
}

// ===== Discovery Helpers =====

func (m *Manager) detectOllama() *struct{ Models []string } {
	resp, err := http.Get("http://127.0.0.1:11434/api/tags")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var body struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	io.LimitReader(resp.Body, m.maxBodyBytes)
	json.NewDecoder(resp.Body).Decode(&body)

	if len(body.Models) == 0 {
		return nil
	}
	out := struct{ Models []string }{Models: make([]string, len(body.Models))}
	for i, mm := range body.Models {
		out.Models[i] = mm.Name
	}
	return &out
}

func (m *Manager) detectLMStudio() *struct{ Models []string } {
	resp, err := http.Get("http://127.0.0.1:1234/v1/models")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, m.maxBodyBytes)).Decode(&body)

	if len(body.Data) == 0 {
		return nil
	}
	out := struct{ Models []string }{Models: make([]string, len(body.Data))}
	for i, d := range body.Data {
		out.Models[i] = d.ID
	}
	return &out
}

func (m *Manager) scanGGUF(dir string) []string {
	var paths []string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".gguf") {
			paths = append(paths, path)
		}
		return nil
	})
	return paths
}

// ===== Internal Helpers =====

func (m *Manager) getLocalBackend() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, ps := range m.localProcesses {
		if ps.proc != nil {
			return "llama/" + id
		}
	}
	return ""
}

func (m *Manager) getCloudBackend() string {
	if p := findProvider("openai"); p != nil && p.APIKey != "" {
		return "openai"
	}
	return ""
}

func findProvider(id string) *ProviderEntry {
	// Placeholder — would load from config
	return nil
}

func formatPrompt(messages []Message) string {
	var b strings.Builder
	for _, m := range messages {
		b.WriteString(m.Role + ": " + m.Content + "\n")
	}
	return b.String()
}

func toJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func splitBackendPrefix(modelID string) (prefix, target string) {
	i := strings.IndexByte(modelID, '/')
	if i < 0 {
		return "", modelID
	}
	return modelID[:i], modelID[i+1:]
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func fileSizeGB(path string) float64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return float64(info.Size()) / (1024 * 1024 * 1024)
}

func (m *Manager) findLlamaServer() string {
	// Search common paths
	candidates := []string{
		filepath.Join(m.llamaDir, "llama-server"),
		filepath.Join(m.llamaDir, "llama-server.exe"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
