// Package tools provides the tool registry and execution framework.
// Each tool has a name, JSON Schema input description, and an async handler.
// Tools are gated by module state (see pkg/module).
package tools

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Tool is a single registered callable tool.
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

// HandlerFunc processes tool arguments and returns a result.
type HandlerFunc func(args map[string]interface{}) (interface{}, error)

// Registry holds all registered tools.
type Registry struct {
	mu      sync.RWMutex
	tools   map[string]*entry
	history []*record
	maxHist int
}

type entry struct {
	Tool    Tool
	Handler HandlerFunc
	modID   string // gating module ID; "" = no gate
}

type record struct {
	Tool     string
	User     string
	Duration time.Duration
	Error    bool
}

// New creates a new empty registry.
func New(maxHistory int) *Registry {
	return &Registry{
		tools:   make(map[string]*entry),
		maxHist: maxHistory,
	}
}

// Register adds a tool to the registry.
func (r *Registry) Register(name, desc string, schema map[string]interface{}, handler HandlerFunc, modID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[name] = &entry{
		Tool:    Tool{Name: name, Description: desc, InputSchema: schema},
		Handler: handler,
		modID:   modID,
	}
}

// List returns all tool definitions.
func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, e := range r.tools {
		out = append(out, e.Tool)
	}
	return out
}

// Call dispatches to the named tool's handler with the given args.
func (r *Registry) Call(name string, user string, args map[string]interface{}) (interface{}, error) {
	r.mu.RLock()
	e, ok := r.tools[name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
	if e.Handler == nil {
		return nil, fmt.Errorf("handler not set for tool: %s", name)
	}
	start := time.Now()
	result, err := e.Handler(args)
	rec := record{Tool: name, User: user, Duration: time.Since(start), Error: err != nil}
	r.appendRecord(rec)
	return result, err
}

// History returns recent execution records (most recent first).
func (r *Registry) History(n int) []record {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if n > len(r.history) {
		n = len(r.history)
	}
	out := make([]record, n)
	copy(out, r.history[len(r.history)-n:])
	// Reverse to most-recent-first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (r *Registry) appendRecord(rec record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.history = append(r.history, rec)
	if len(r.history) > r.maxHist {
		r.history = r.history[len(r.history)-r.maxHist:]
	}
}

// === Builtin Tool Factories ===
// These create standard tool schemas — called once during startup.

// StatusTool describes system status info (no args).
func StatusTool(handler func() (interface{}, error)) *Registry {
	r := New(500)
	r.Register("tars_status", "Get gateway status, statistics, device and model info.",
		map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		func(args map[string]interface{}) (interface{}, error) {
			return handler()
		}, "")
	return r
}

// TimeTool returns current local time (no args).
func TimeTool() *Registry {
	r := New(0)
	r.Register("tars_time", "Get the current local date and time.",
		map[string]interface{}{"type": "object"},
		func(args map[string]interface{}) (interface{}, error) {
			now := time.Now()
			return map[string]interface{}{
				"datetime": now.Format("2006-01-02 15:04:05 MST"),
				"date":     now.Format("2006-01-02"),
				"time":     now.Format("15:04:05"),
				"weekday":  now.Weekday(),
				"unix":     now.Unix(),
			}, nil
		}, "")
	return r
}

// SystemInfoTool returns hardware overview.
func SystemInfoTool(handler func() (interface{}, error)) *Registry {
	r := New(0)
	r.Register("tars_system_info", "Get system hardware, memory, CPU and disk information.",
		map[string]interface{}{"type": "object"},
		func(args map[string]interface{}) (interface{}, error) {
			return handler()
		}, "")
	return r
}

// FileListTool lists directory contents with path safety checks.
func FileListTool(pathAllowed func(string) bool) *Registry {
	r := New(0)
	r.Register("tars_file_list", "List directory contents. Path must be in allowed roots.",
		map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string", "description": "Directory path to list"},
			},
			"required": []string{"path"},
		},
		func(args map[string]interface{}) (interface{}, error) {
			path, _ := args["path"].(string)
			if !pathAllowed(path) {
				return map[string]interface{}{"error": "path not in authorized read scope"}, nil
			}
			return listDir(path)
		}, "builtinTools")
	return r
}

// FileReadTool reads file content with size limit and path safety.
func FileReadTool(pathAllowed func(string) bool, maxBytes int64) *Registry {
	r := New(0)
	r.Register("tars_file_read", "Read file content. Path must be in allowed roots. Max 5MB.",
		map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]interface{}{"type": "string", "description": "File path to read"},
			},
			"required": []string{"path"},
		},
		func(args map[string]interface{}) (interface{}, error) {
			path, _ := args["path"].(string)
			if !pathAllowed(path) {
				return map[string]interface{}{"error": "path not in authorized read scope"}, nil
			}
			b, err := readFileLimited(path, maxBytes)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"content": string(b)}, nil
		}, "builtinTools")
	return r
}

func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	// Placeholder: real implementation uses io.LimitReader on os.Open
	return nil, fmt.Errorf("not implemented — wire os.ReadFile + io.LimitReader")
}

func listDir(path string) (interface{}, error) {
	// Placeholder: real implementation uses os.ReadDir
	return nil, fmt.Errorf("not implemented — wire os.ReadDir")
}
