// TarsCore 2.0 — Enterprise-Grade Unified AI Security Gateway
// Architecture Inspired by: Tencent NT · Alibaba Sentinel · ByteDance Middle Platform
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HP-jh/TarsCore/pkg/config"
	"github.com/HP-jh/TarsCore/pkg/gateway"
	"github.com/HP-jh/TarsCore/pkg/i18n"
	"github.com/HP-jh/TarsCore/pkg/mcp/server"
	"github.com/HP-jh/TarsCore/pkg/memory/shared"
	"github.com/HP-jh/TarsCore/pkg/models"
	"github.com/HP-jh/TarsCore/pkg/module"
	"github.com/HP-jh/TarsCore/pkg/platform"
	"github.com/HP-jh/TarsCore/pkg/router"
	"github.com/HP-jh/TarsCore/pkg/security/gatekeeper"
	"github.com/HP-jh/TarsCore/pkg/security/waf"
	"github.com/HP-jh/TarsCore/pkg/tools"
	"github.com/HP-jh/TarsCore/version"
	
	"github.com/HP-jh/TarsCore/pkg/auth/rbac"
	"github.com/HP-jh/TarsCore/pkg/health/circuit"
)

const (
	port          = 18889
	modelPort     = 18890
	apiKeyDefault = "tars-gateway-key"
)

var (
	cfg       *config.Config
	authCfg   interface{}
	mgr       *models.Manager
	tReg      *tools.Registry
	evHub     *eventHub
	st        statsStore
	configFn  string
	i18nEngine *i18n.Engine
	sharedMem  *shared.Store
)

func init() {
	// Resolve config path
	configFn = os.Getenv("TSG_CONFIG")
	if configFn == "" {
		home, _ := os.UserHomeDir()
		configFn = home + "/.tarscore/config.json"
	}
	
	var err error
	cfg, err = config.Load(configFn)
	if err != nil {
		log.Printf("[WARN] config %s: %v, using defaults", configFn, err)
		d := config.DefaultConfig()
		cfg = d
	}
	
	// Initialize subsystems
	authCfg = rbac.New(cfg.Security.APIKey, cfg.Users...)
	mgr = models.New(cfg.Paths.ModelDir, cfg.Paths.LlamaDir)
	tReg = tools.New(500)
	registerBuiltinTools(tReg, mgr)
	module.SetConfigPath(configFn)
	module.InitDefaults()
	if cfg.Modules != nil {
		module.Apply(cfg.Modules)
	}
	router.Setup(os.Getenv("TSG_STATE_DIR") + "/router.json")
	evHub = newEventHub(1024)
	go evHub.run(context.Background())
	
	// Initialize i18n engine
	i18nEngine = i18n.NewEngine()
	i18nEngine.SetCurrentLang(i18n.ZH)
	
	// Initialize shared memory
	sharedMem = shared.New()
}

func main() {
	log.Printf("=== TarsCore v%s ===", version.String())
	
	// Subcommands
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "doctor":
			doctorRun()
			return
		case "version", "-v", "--version":
			fmt.Println("TarsCore " + version.String())
			return
		case "mcp-stdio":
			mcpStdioRun()
			return
		case "update":
			updateCheckRun()
			return
		}
	}
	
	// Interactive setup wizard for first-time users
	if !hasConfigBeenSetUp() {
		fmt.Println("\n🚀 Welcome to TarsCore 2.0!")
		fmt.Println("Enterprise-Grade Unified AI Security Gateway\n")
		fmt.Println("Quick Setup Wizard:\n")
		
		mode := selectMode()
		log.Printf("Selected mode: %s", mode)
		
		provider := selectProvider()
		if provider != "" {
			baseURL, apiKey := getProviderCredentials(provider)
			cfg.Cloud.BaseURL = baseURL
			cfg.Cloud.APIKey = apiKey
		}
		
		cfg.Security.WAFFEnabled = promptBool("Enable WAF protection?", true)
		cfg.Traffic.GlobalQPS = promptInt("Set global QPS limit:", 1000)
		
		if err := cfg.Save(configFn); err != nil {
			log.Fatalf("[ERROR] Failed to save config: %v", err)
		}
		
		fmt.Println("\n✅ Configuration saved successfully!")
	}
	
	// Discover local models
	localModels := mgr.DiscoverLocal()
	log.Printf("Discovered %d local models (GGUF/Ollama/LMStudio)", len(localModels))
	
	// Build and start HTTP server
	h := buildHandlerChain()
	srv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", port),
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      600 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	
	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[SHUTDOWN] Graceful shutdown...")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	
	log.Printf("Listening on http://127.0.0.1:%d", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
	log.Println("[OK] Server shut down cleanly.")
}

// ===== Interactive Setup Wizard =====

func hasConfigBeenSetUp() bool {
	if _, err := os.Stat(configFn); os.IsNotExist(err) {
		return false
	}
	return true
}

func selectMode() string {
	fmt.Println("Select operating mode:")
	fmt.Println("  1. Local Only (Ollama/GGUF/LMStudio)")
	fmt.Println("  2. Cloud Enabled (OpenAI/DeepSeek)")
	fmt.Print("Choice [1-2]: ")
	var choice string
	fmt.Scanln(&choice)
	if choice == "2" { return "cloud" }
	return "local"
}

func selectProvider() string {
	fmt.Println("\nSelect cloud provider:")
	fmt.Println("  1. OpenAI")
	fmt.Println("  2. DeepSeek")
	fmt.Println("  3. Custom URL")
	fmt.Print("Choice [1-3]: ")
	var choice string
	fmt.Scanln(&choice)
	switch choice {
	case "1": return "openai"
	case "2": return "deepseek"
	case "3": return "custom"
	default: return ""
	}
}

func getProviderCredentials(provider string) (baseURL, apiKey string) {
	if provider == "openai" {
		return "https://api.openai.com/v1", promptInput("Enter OpenAI API key: ")
	} else if provider == "deepseek" {
		return "https://api.deepseek.com/v1", promptInput("Enter DeepSeek API key: ")
	}
	baseURL = promptInput("Enter custom base URL: ")
	apiKey = promptInput("Enter API key: ")
	return
}

func promptInput(prompt string) string {
	fmt.Print(prompt)
	var input string
	fmt.Scanln(&input)
	return input
}

func promptBool(prompt string, defaultVal bool) bool {
	fmt.Print(prompt + " (y/n): ")
	var resp string
	fmt.Scanln(&resp)
	return strings.EqualFold(resp, "y") || strings.EqualFold(resp, "yes")
}

func promptInt(prompt string, defaultVal int) int {
	fmt.Print(prompt + fmt.Sprintf(" [%d]: ", defaultVal))
	var input string
	fmt.Scanln(&input)
	if input == "" {
		return defaultVal
	}
	// Simplified - would use fmt.Sscanf in production
	return defaultVal
}

// ===== HTTP Chain Builder =====

func buildHandlerChain() http.Handler {
	mux := http.NewServeMux()
	
	// Public endpoints
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/", serveFrontend)
	mux.HandleFunc("/metrics", handleMetrics)
	
	// Authenticated API
	mux.HandleFunc("/api/status", authN(handleStatus))
	mux.HandleFunc("/api/chat/completions", authN(modGuard("chatApi", handleChat)))
	mux.HandleFunc("/api/tools/", authN(modGuard("builtinTools", handleToolCall)))
	
	// Admin endpoints
	mux.HandleFunc("/api/admin/models", admin(handler(handleModelsList)))
	mux.HandleFunc("/api/admin/models/start", admin(handler(handleModelStart)))
	mux.HandleFunc("/api/admin/models/stop", admin(handler(handleModelStop)))
	mux.HandleFunc("/api/admin/config", admin(handler(handleConfigGet)))
	mux.HandleFunc("/api/admin/modules", admin(handler(handleModulesList)))
	mux.HandleFunc("/api/admin/logs", admin(handler(handleLogs)))
	mux.HandleFunc("/api/admin/audit-logs", admin(handler(handleAuditLogs)))
	mux.HandleFunc("/api/admin/update/check", admin(handler(handleUpdateCheck)))
	mux.HandleFunc("/api/admin/update/apply", admin(handler(handleUpdateApply)))
	mux.HandleFunc("/api/v1/mcp/marketplace", authN(handleMCPMarketplace))
	
	// SSE/WS
	mux.HandleFunc("/ws/events/stream", handleSSEStream)
	mux.HandleFunc("/ws/events", handleWS)
	mux.HandleFunc("/mcp", authN(modGuard("mcpExternal", handleMCP)))
	
	// OAuth flows
	mux.HandleFunc("/oauth/login", handleOAuthLogin)
	mux.HandleFunc("/oauth/callback", handleOAuthCallback)
	mux.HandleFunc("/oauth/logout", handleOAuthLogout)
	
	// i18n endpoints
	mux.HandleFunc("/api/i18n/bundle", handleI18nBundle)
	mux.HandleFunc("/api/i18n/t", handleI18nTranslate)
	mux.HandleFunc("/api/i18n/languages", handleI18nLanguages)
	mux.HandleFunc("/api/i18n/dashboard", handleI18nDashboard)
	
	// Additional admin routes
	for _, r := range []string{"/api/admin/shutdown", "/api/admin/selfprotect/status", "/api/admin/av-compat/status"} {
		mux.HandleFunc(r, handler(func(w http.ResponseWriter, r *http.Request) {}))
	}
	
	// Apply middleware chain
	return gateway.Chain(gateway.Config{
		WAFMode:   waf.Normal,
		AuthConfig: authCfg,
	}, mux)
}

// ===== Middleware Helpers =====

type ctxKey string

func authN(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := extractAPIKey(r)
		user, role, ok := verifyAuth(key)
		if !ok {
			jsonErr(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user, role)))
	}
}

func admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role := getUserRole(r)
		if role != "admin" && role != "global_admin" {
			jsonErr(w, http.StatusForbidden, map[string]string{"error": "admin privilege required"})
			return
		}
		next.ServeHTTP(w, r)
	}
}

func modGuard(id string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !module.Enabled(id) {
			jsonErr(w, http.StatusServiceUnavailable, map[string]string{
				"error": "module " + id + " disabled",
				"hint":  "config modules." + id + "=true",
			})
			return
		}
		next.ServeHTTP(w, r)
	}
}

func handler(h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h(w, r)
	}
}

// ===== Handlers =====

func handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{
		"status":   "ok",
		"uptime":   time.Since(st.start).String(),
		"version":  version.String(),
		"pid":      os.Getpid(),
		"go":       runtime.Version(),
		"os":       runtime.GOOS + "/" + runtime.GOARCH,
		"cpus":     runtime.NumCPU(),
		"modules":  len(module.List()),
		"providers": providers.Count(),
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{
		"total_requests": st.totalReq,
		"success":        st.success,
		"failed":         st.fail,
		"waf_blocks":     st.wafBlocks,
		"running_models": len(mgr.GetRunning()),
		"modules":        module.List(),
		"last_waf_log":   st.lastWAF,
		"languages":      i18nEngine.GetLanguages(),
	})
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	type chatReq struct {
		Model     string      `json:"model"`
		Messages  []models.Message `json:"messages"`
		MaxTokens int         `json:"max_tokens"`
	}
	var req chatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, map[string]string{"error": "bad request body"})
		return
	}
	if len(req.Messages) == 0 {
		jsonErr(w, http.StatusBadRequest, map[string]string{"error": "at least one message required"})
		return
	}
	if req.MaxTokens == 0 {
		req.MaxTokens = 4096
	}
	res, err := mgr.Chat(req.Model, req.Messages, req.MaxTokens)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, map[string]string{"error": "chat: " + err.Error()})
		return
	}
	evHub.push(EventChat, res.Content, getUser(r), r.URL.Path)
	jsonOut(w, map[string]interface{}{
		"content": res.Content,
		"backend": res.Backend,
	})
}

func handleToolCall(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/tools/")
	name := strings.Split(path, "/")[0]
	if name == "" {
		jsonErr(w, http.StatusBadRequest, map[string]string{"error": "tool name required"})
		return
	}
	var args map[string]interface{}
	json.NewDecoder(r.Body).Decode(&args)
	act, reason := gatekeeper.Decide(name, args, cfg.Gatekeeper.Rules)
	switch act {
	case gatekeeper.Deny:
		st.audit("GATEKEEPER_DENY", getUser(r)+":"+reason)
		jsonErr(w, http.StatusForbidden, map[string]string{"error": reason})
		return
	case gatekeeper.Confirm:
		tok, exp, err := gatekeeper.IssueToken(getUser(r), name, args)
		if err != nil {
			jsonErr(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
			return
		}
		jsonOut(w, map[string]interface{}{
			"confirmation_required": true,
			"confirm_token":         tok,
			"expires_at":            exp.Format(time.RFC3339),
			"reason":                reason,
			"hint":                  "Re-call with argument confirm_token=" + tok,
		})
		return
	}
	result, err := tReg.Call(name, getUser(r), args)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	jsonOut(w, result)
}

func handleModelsList(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{
		"all":       mgr.ListAll(),
		"running":   mgr.GetRunning(),
		"discovered": mgr.DiscoverLocal(),
	})
}

func handleModelStart(w http.ResponseWriter, r *http.Request) {
	var req struct{ Model string `json:"model"` }
	json.NewDecoder(r.Body).Decode(&req)
	if req.Model == "" {
		req.Model = "qwen2.5-3b"
	}
	ggufs := scanGGUF(mgr.ModelDir())
	if len(ggufs) == 0 {
		jsonErr(w, http.StatusBadRequest, map[string]string{"error": "no .gguf files found"})
		return
	}
	err := mgr.StartLocal(req.Model, ggufs[0], modelPort)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	jsonOut(w, map[string]interface{}{"success": true, "model": req.Model, "port": modelPort})
}

func handleModelStop(w http.ResponseWriter, r *http.Request) {
	if err := mgr.StopLocal(""); err != nil {
		jsonErr(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	jsonOut(w, map[string]interface{}{"success": true, "running": false})
}

func handleConfigGet(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, cfg)
}

func handleModulesList(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			ID      string `json:"id"`
			Enabled *bool  `json:"enabled"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.ID != "" && req.Enabled != nil {
			if err := module.Toggle(req.ID, *req.Enabled); err != nil {
				jsonErr(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
		}
		jsonOut(w, map[string]interface{}{"success": true})
		return
	}
	jsonOut(w, module.List())
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, st.logs(200))
}

func handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, st.audits(200))
}

func handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{
		"current": version.String(),
		"latest":  version.String(),
		"available": false,
	})
}

func handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{"applied": false, "note": "not implemented yet"})
}

func handleMCP(w http.ResponseWriter, r *http.Request) {
	list := tReg.List()
	jsonOut(w, map[string]interface{}{"total": len(list), "tools": list})
}

func handleMCPMarketplace(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{"marketplace": "placeholder", "total": 0})
}

func handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	jsonErr(w, http.StatusNotImplemented, map[string]string{"error": "OAuth not implemented yet"})
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	jsonErr(w, http.StatusNotImplemented, map[string]string{"error": "OAuth not implemented yet"})
}

func handleOAuthLogout(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func handleI18nBundle(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{
		"bundles": i18nEngine.GetLanguages(),
		"default": i18nEngine.GetCurrentLang(),
	})
}

func handleI18nTranslate(w http.ResponseWriter, r *http.Request) {
	type tr struct {
		Key   string `json:"key"`
		Lang  string `json:"lang"`
		Text  string `json:"text"`
	}
	var req tr
	json.NewDecoder(r.Body).Decode(&req)
	translated := i18nEngine.Translate(req.Key, i18n.Language(req.Lang))
	jsonOut(w, map[string]interface{}{"translated": translated})
}

func handleI18nLanguages(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{
		"languages": []string{"zh", "en", "ja", "ko", "ru", "ar", "fr"},
		"default":   i18nEngine.GetCurrentLang(),
	})
}

func handleI18nDashboard(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{
		"coverage": i18nEngine.GetCoverage(),
		"langs":    i18nEngine.GetLanguages(),
	})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]interface{}{
		"total_requests":   st.totalReq,
		"success":          st.success,
		"fail":             st.fail,
		"waf_blocks":       st.wafBlocks,
		"uptime_seconds":   time.Since(st.start).Seconds(),
		"active_modules":   activeModuleCount(),
		"cache_size":       platformCacheSize(),
		"registered_tools": tReg.Total(),
	})
}

func handleSSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			data, _ := json.Marshal(evHub.recent(50))
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "WebSocket — wire gorilla/websocket implementation", http.StatusNotImplemented)
}

func serveFrontend(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := `<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>TarsCore</title></head><body>` +
			`<h1>TarsCore v` + version.String() + `</h1>` +
			`<p>Enterprise AI Security Gateway running.</p>` +
			`<ul>` +
			`<li>Health: <a href="/health">/health</a></li>` +
			`<li>Metrics: <a href="/metrics">/metrics</a></li>` +
			`<li>Status: <a href="/api/status">/api/status</a></li>` +
			`</ul></body></html>`
		w.Write([]byte(html))
		return
	}
	http.FileServer(http.Dir("frontend/static")).ServeHTTP(w, r)
}

// ===== Subcommands =====

func doctorRun() {
	fmt.Println("=== TarsCore Doctor ===")
	fmt.Printf("  Version: %s\n", version.String())
	fmt.Printf("  Config: %s\n", configFn)
	fmt.Printf("  Port: %d | PID: %d\n", port, os.Getpid())
	fmt.Printf("  Go: %s | OS: %s/%s | CPUs: %d\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	fmt.Printf("  Models discovered: %d\n", len(mgr.DiscoverLocal()))
	fmt.Printf("  Modules: %d registered\n", len(module.List()))
	fmt.Printf("  Providers: %d registered\n", providers.Count())
	fmt.Printf("  Tools: %d registered\n", tReg.Total())
	fmt.Printf("  Languages: %v\n", i18nEngine.GetLanguages())
	fmt.Println("  [DONE]")
}

func mcpStdioRun() {
	srv := server.New("tarscore-mcp", version.String())
	for _, t := range tReg.List() {
		srv.RegisterTool(t.Name, t.Description, t.InputSchema,
			func(args map[string]interface{}) (interface{}, error) {
				return tReg.Call(t.Name, "mcp-stdin", args)
			},
		)
	}
	srv.Run()
}

func updateCheckRun() {
	result := map[string]interface{}{"current": version.String()}
	data, _ := json.MarshalIndent(result, "", "  ")
	os.Stdout.Write(data)
	os.Stdout.WriteString("\n")
	os.Exit(0)
}

// ===== Event Hub =====

type EventType string

const (
	EventChat  EventType = "chat"
	EventBlock EventType = "block"
	EventWarn  EventType = "warn"
	EventStat  EventType = "stat"
)

type eventData struct {
	Type   EventType `json:"type"`
	Time   string    `json:"time"`
	Data   interface{} `json:"data"`
	User   string    `json:"user,omitempty"`
	Path   string    `json:"path,omitempty"`
}

type eventHub struct {
	buf     []eventData
	head, tail, count int
	cap   int
	mu    sync.RWMutex
}

func newEventHub(capacity int) *eventHub {
	return &eventHub{buf: make([]eventData, capacity), cap: capacity}
}

func (e *eventHub) push(typ EventType, data interface{}, user, path string) {
	e.mu.Lock()
	item := eventData{Type: typ, Time: time.Now().Format(time.RFC3339), Data: data, User: user, Path: path}
	e.buf[e.tail] = item
	e.tail = (e.tail + 1) % e.cap
	if e.count < e.cap {
		e.count++
	} else {
		e.head = (e.head + 1) % e.cap
	}
	e.mu.Unlock()
}

func (e *eventHub) recent(n int) []eventData {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if n > e.count {
		n = e.count
	}
	out := make([]eventData, n)
	idx := e.tail
	for i := 0; i < n; i++ {
		idx = (idx - 1 + e.cap) % e.cap
		out[n-1-i] = e.buf[idx]
	}
	return out
}

func (e *eventHub) run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.push(EventStat, map[string]interface{}{"status": "alive"}, "system", "")
		}
	}
}

// ===== Stats Store =====

type statsStore struct {
	start      time.Time
	totalReq, success, fail, wafBlocks int
	logs_      []string
	auids      []eventData
	mu         sync.Mutex
	maxLogLen  = 5000
	maxAudLen  = 2000
	lastWAF    string
}

func (s *statsStore) record(ok bool, blocked bool) {
	s.mu.Lock()
	s.totalReq++
	if blocked {
		s.wafBlocks++
	} else if ok {
		s.success++
	} else {
		s.fail++
	}
	s.mu.Unlock()
}

func (s *statsStore) addLog(msg string) {
	s.mu.Lock()
	s.logs_ = append(s.logs_, msg)
	if len(s.logs_) > s.maxLogLen {
		s.logs_ = s.logs_[len(s.logs_)-2000:]
	}
	s.mu.Unlock()
}

func (s *statsStore) audit(tag, detail string) {
	s.mu.Lock()
	s.auids = append(s.auids, eventData{
		Type: "audit",
		Time: time.Now().Format(time.RFC3339),
		Data: map[string]string{"tag": tag, "detail": detail},
	})
	if len(s.auids) > s.maxAudLen {
		s.auids = s.auids[len(s.auids)-500:]
	}
	s.mu.Unlock()
}

func (s *statsStore) logs(n int) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > len(s.logs_) {
		n = len(s.logs_)
	}
	if n == 0 {
		return nil
	}
	start := len(s.logs_) - n
	out := make([]string, n)
	copy(out, s.logs_[start:])
	return out
}

func (s *statsStore) audits(n int) []eventData {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > len(s.auids) {
		n = len(s.auids)
	}
	out := make([]eventData, n)
	copy(out, s.auids[len(s.auids)-n:])
	return out
}

// ===== Utility Helpers =====

func extractAPIKey(r *http.Request) string {
	if k := r.Header.Get("X-API-Key"); k != "" {
		return k
	}
	if k := r.Header.Get("Authorization"); strings.HasPrefix(k, "Bearer ") {
		return k[7:]
	}
	return r.URL.Query().Get("apiKey")
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		i := strings.Index(xff, ",")
		if i > 0 {
			return xff[:i]
		}
		return xff
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	return r.RemoteAddr
}

func getUser(r *http.Request) string {
	if u := r.Context().Value(ctxKey("user")); u != nil {
		return u.(string)
	}
	return "anonymous"
}

func getUserRole(r *http.Request) string {
	if u := r.Context().Value(ctxKey("role")); u != nil {
		return u.(string)
	}
	return "user"
}

func withUser(ctx context.Context, user, role string) context.Context {
	ctx = context.WithValue(ctx, ctxKey("user"), user)
	return context.WithValue(ctx, ctxKey("role"), role)
}

func jsonOut(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, m map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(m)
}

func scanGGUF(dir string) []string {
	var paths []string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(p), ".gguf") {
			paths = append(paths, p)
		}
		return nil
	})
	return paths
}

// ===== Helper Functions (would be imported from packages) =====

func verifyAuth(key string) (user, role string, ok bool) {
	// Placeholder: real implementation in pkg/auth/rbac
	if key == "" {
		return "", "", false
	}
	return "default", "admin", true
}

func activeModuleCount() int {
	count := 0
	for _, m := range module.List() {
		if enabled, _ := m["enabled"].(bool); enabled {
			count++
		}
	}
	return count
}

func platformCacheSize() int {
	return 0 // Would query actual cache implementation
}

func providers.Count() int {
	return 0 // Would return actual provider count
}
