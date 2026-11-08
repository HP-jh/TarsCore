// Package platform provides the centralized capability center inspired by ByteDance's middle-platform thinking.
// Implements model lifecycle management, unified tool execution, and session memory system.
package platform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ===== Provider Interface =====

type Provider interface {
	Name() string
	Type() string // openai | anthropic | ollama | lmstudio | local_gguf
	BaseURL() string
	APIKey() string
	Models() []ModelInfo
	Chat(req ChatRequest) (*ChatResponse, error)
	HealthCheck() bool
}

type ModelInfo struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Status      string  `json:"status"` // idle | loading | ready | error
	Port        int     `json:"port,omitempty"`
	GGUFPath    string  `json:"gguf_path,omitempty"`
	SizeGB      float64 `json:"size_gb,omitempty"`
	Backend     string  `json:"backend,omitempty"`
	BaseURL     string  `json:"base_url,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	Model     string    `json:"model"`
	Messages  []Message `json:"messages"`
	MaxTokens int       `json:"max_tokens"`
	Temperature float64 `json:"temperature"`
}

type ChatResponse struct {
	Content string  `json:"content"`
	Backend string  `json:"backend"`
	Latency time.Duration `json:"latency"`
	Error   string  `json:"error,omitempty"`
}

// ===== Manager for All Models =====

type Manager struct {
	mu              sync.RWMutex
	providers       map[string]Provider
	localProcesses  map[string]*processState
	modelDir        string
	llamaDir        string
	maxBodyBytes    int64
	discoveryTicker *time.Ticker
}

type processState struct {
	cmd      interface{} // simplified - would use exec.Cmd in production
	port     int
	output   bytes.Buffer
	started  time.Time
	ggufPath string
}

func NewManager(modelDir, llamaDir string) *Manager {
	mgr := &Manager{
		providers:      make(map[string]Provider),
		localProcesses: make(map[string]*processState),
		modelDir:       modelDir,
		llamaDir:       llamaDir,
		maxBodyBytes:   5 << 20, // 5 MB
	}
	
	go mgr.autoDiscoveryLoop()
	return mgr
}

func (mgr *Manager) RegisterProvider(p Provider) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.providers[p.Name()] = p
}

func (mgr *Manager) GetProvider(name string) Provider {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	return mgr.providers[name]
}

func (mgr *Manager) ListAllProviders() []string {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	names := make([]string, 0, len(mgr.providers))
	for name := range mgr.providers {
		names = append(names, name)
	}
	return names
}

func (mgr *Manager) DiscoverLocal() []ModelInfo {
	var models []ModelInfo
	
	if o := mgr.detectOllama(); o != nil {
		for _, id := range o.Models {
			models = append(models, ModelInfo{
				ID: id, Name: id, Type: "ollama", Backend: "ollama",
				BaseURL: "http://127.0.0.1:11434", Status: "ready", Port: 11434,
			})
		}
	}
	
	if l := mgr.detectLMStudio(); l != nil {
		for _, id := range l.Models {
			models = append(models, ModelInfo{
				ID: id, Name: id, Type: "lmstudio", Backend: "lmstudio",
				BaseURL: "http://127.0.0.1:1234", Status: "ready", Port: 1234,
			})
		}
	}
	
	if ggufs := mgr.scanGGUF(mgr.modelDir); len(ggufs) > 0 {
		for _, g := range ggufs {
			id := strings.TrimSuffix(filepath.Base(g), filepath.Ext(g))
			sizeGB := fileSizeGB(g)
			models = append(models, ModelInfo{
				ID: id, Name: id, Type: "local_gguf", Backend: "llama",
				Status: "idle", GGUFPath: g, SizeGB: sizeGB,
			})
		}
	}
	
	return models
}

func (mgr *Manager) StartLocal(modelID, ggufPath string, port int) error {
	bin := mgr.findLlamaServer()
	if bin == "" {
		return fmt.Errorf("llama-server binary not found in %s", mgr.llamaDir)
	}
	
	ps := &processState{port: port, started: time.Now(), ggufPath: ggufPath}
	mgr.localProcesses[modelID] = ps
	
	go func() {
		time.Sleep(5 * time.Second) // simulate warmup
		ps.output.WriteString("LLaMA server initialized")
	}()
	
	return nil
}

func (mgr *Manager) StopLocal(modelID string) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	
	if ps, ok := mgr.localProcesses[modelID]; ok {
		if ps.proc != nil {
			ps.cmd.(*os.Process).Kill()
		}
		delete(mgr.localProcesses, modelID)
	}
	return nil
}

func (mgr *Manager) Chat(req ChatRequest) (*ChatResponse, error) {
	if req.Model == "" || req.Model == "auto" {
		if active := mgr.getLocalBackend(); active != "" {
			result, err := mgr.chatToBackend(active, req)
			if err == nil {
				return result, nil
			}
		}
		if cloud := mgr.getCloudBackend(); cloud != "" {
			return mgr.chatToCloud(cloud, req)
		}
		return nil, fmt.Errorf("no available backend (local or cloud)")
	}
	
	prefix, target := splitBackendPrefix(req.Model)
	switch prefix {
	case "ollama":
		return mgr.chatToOllama(target, req)
	case "lmstudio":
		return mgr.chatToLMStudio(target, req)
	case "llama":
		return mgr.chatToLocal(target, req)
	default:
		if p, ok := mgr.providers[req.Model]; ok {
			return p.Chat(req)
		}
		return mgr.chatToLocal(req.Model, req)
	}
}

func (mgr *Manager) GetRunning() []ModelInfo {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	var running []ModelInfo
	for id, ps := range mgr.localProcesses {
		if ps.proc != nil {
			running = append(running, ModelInfo{
				ID: id, Name: id, Type: "local_gguf", Backend: "llama",
				Status: "running", Port: ps.port, GGUFPath: ps.ggufPath,
			})
		}
	}
	return running
}

// ===== Discovery Methods =====

func (mgr *Manager) detectOllama() *struct{ Models []string } {
	resp, err := http.Get("http://127.0.0.1:11434/api/tags")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	var body struct{ Models []struct{ Name string } }
	json.NewDecoder(io.LimitReader(resp.Body, mgr.maxBodyBytes)).Decode(&body)
	
	if len(body.Models) == 0 { return nil }
	out := struct{ Models []string }{}
	for i, m := range body.Models {
		out.Models[i] = m.Name
	}
	return &out
}

func (mgr *Manager) detectLMStudio() *struct{ Models []string } {
	resp, err := http.Get("http://127.0.0.1:1234/v1/models")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	
	var body struct{ Data []struct{ ID string } }
	json.NewDecoder(io.LimitReader(resp.Body, mgr.maxBodyBytes)).Decode(&body)
	
	if len(body.Data) == 0 { return nil }
	out := struct{ Models []string }{}
	for i, d := range body.Data {
		out.Models[i] = d.ID
	}
	return &out
}

func (mgr *Manager) scanGGUF(dir string) []string {
	var paths []string
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() { return nil }
		if strings.HasSuffix(strings.ToLower(path), ".gguf") {
			paths = append(paths, path)
		}
		return nil
	})
	return paths
}

func (mgr *Manager) autoDiscoveryLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		_ = mgr.DiscoverLocal() // discovery already happens
	}
}

// ===== Backend Chat Methods =====

func (mgr *Manager) getLocalBackend() string {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	for id := range mgr.localProcesses {
		return "llama/" + id
	}
	return ""
}

func (mgr *Manager) getCloudBackend() string {
	return "openai" // placeholder
}

func (mgr *Manager) chatToLocal(modelID string, req ChatRequest) (*ChatResponse, error) {
	ps, ok := mgr.localProcesses[modelID]
	if !ok || ps.proc == nil {
		return nil, fmt.Errorf("local model %s not running", modelID)
	}
	
	payload, _ := json.Marshal(map[string]interface{}{
		"prompt": formatPrompt(req.Messages),
		"max_tokens": req.MaxTokens,
		"temperature": req.Temperature,
	})
	
	start := time.Now()
	resp, err := http.Post(
		fmt.Sprintf("http://127.0.0.1:%d/completion", ps.port),
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("chat failed: %w", err)
	}
	defer resp.Body.Close()
	
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, mgr.maxBodyBytes))
	var result struct{ Text string }
	json.Unmarshal(raw, &result)
	
	return &ChatResponse{
		Content: result.Text,
		Backend: "llama/" + modelID,
		Latency: time.Since(start),
	}, nil
}

func (mgr *Manager) chatToOllama(modelID string, req ChatRequest) (*ChatResponse, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"model": modelID,
		"messages": toJSON(req.Messages),
		"max_tokens": req.MaxTokens,
		"stream": false,
	})
	
	start := time.Now()
	resp, err := http.Post("http://127.0.0.1:11434/api/chat", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("ollama chat failed: %w", err)
	}
	defer resp.Body.Close()
	
	var result struct{ Message struct{ Content string } }
	json.NewDecoder(io.LimitReader(resp.Body, mgr.maxBodyBytes)).Decode(&result)
	
	return &ChatResponse{
		Content: result.Message.Content,
		Backend: "ollama/" + modelID,
		Latency: time.Since(start),
	}, nil
}

func (mgr *Manager) chatToLMStudio(modelID string, req ChatRequest) (*ChatResponse, error) {
	return mgr.chatViaHTTP("http://127.0.0.1:1234", req)
}

func (mgr *Manager) chatToCloud(endpoint string, req ChatRequest) (*ChatResponse, error) {
	return mgr.chatViaHTTP(fmt.Sprintf("%s/v1", endpoint), req)
}

func (mgr *Manager) chatViaHTTP(baseURL string, req ChatRequest) (*ChatResponse, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"messages": toJSON(req.Messages),
		"max_tokens": req.MaxTokens,
	})
	
	start := time.Now()
	resp, err := http.Post(baseURL+"/chat/completions", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("HTTP chat failed: %w", err)
	}
	defer resp.Body.Close()
	
	var result struct{ Choices []struct{ Message struct{ Content string } } }
	json.NewDecoder(io.LimitReader(resp.Body, mgr.maxBodyBytes)).Decode(&result)
	
	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("empty HTTP response")
	}
	
	return &ChatResponse{
		Content: result.Choices[0].Message.Content,
		Backend: baseURL,
		Latency: time.Since(start),
	}, nil
}

func (mgr *Manager) findLlamaServer() string {
	candidates := []string{
		filepath.Join(mgr.llamaDir, "llama-server"),
		filepath.Join(mgr.llamaDir, "llama-server.exe"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func (mgr *Manager) ModelDir() string { return mgr.modelDir }

// ===== Helper Functions =====

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

func fileSizeGB(path string) float64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return float64(info.Size()) / (1024 * 1024 * 1024)
}
