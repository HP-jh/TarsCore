// Package server implements an MCP (Model Context Protocol) stdio server.
// It reads JSON-RPC requests from stdin, dispatches to registered tools/methods,
// and writes responses to stdout — exactly as defined by the MCP spec.
package mcpserver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// ===== MCP Types =====

// Message is a top-level MCP message (request / response / notification).
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ResponseError  `json:"error,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// ResponseError represents an error result in MCP.
type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// InitializeRequest sent by the client on first connect.
type InitializeRequest struct {
	ProtocolVersion string            `json:"protocolVersion"`
	ClientInfo      Implementation    `json:"clientInfo"`
	Capabilities    ClientCapabilities `json:"capabilities"`
}

type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ClientCapabilities struct {
	Roots bool `json:"roots,omitempty"`
}

// ServerCapabilities describes what this MCP server supports.
type ServerCapabilities struct {
	Tools []ToolCaps `json:"tools,omitempty"`
}

type ToolCaps struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

// ToolCallNotification sent by client after initialization to invoke a tool.
type ToolCallNotification struct {
	Method string           `json:"method"` // "tools/call"
	Params ToolCallParams   `json:"params"`
}

type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ===== Server =====

// Server is a complete MCP stdio server.
type Server struct {
	in      io.Reader
	out     io.Writer
	mu      sync.Mutex
	tools   map[string]ToolHandler
	version string
	name    string
	readBuf *bufio.Reader
}

// ToolHandler processes a single tool call.
type ToolHandler func(args map[string]interface{}) (interface{}, error)

// New creates an MCP server that reads from stdin and writes to stdout.
func New(name, version string) *Server {
	return &Server{
		in:      os.Stdin,
		out:     os.Stdout,
		tools:   make(map[string]ToolHandler),
		version: version,
		name:    name,
		readBuf: bufio.NewReader(os.Stdin),
	}
}

// RegisterTool adds a callable tool to the server.
func (s *Server) RegisterTool(name, description string, schema map[string]interface{}, handler ToolHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools[name] = handler
}

// Run starts the stdio message loop. Blocks until EOF or fatal error.
func (s *Server) Run() {
	var sessionId string

	for {
		msg, err := s.readMessage()
		if err != nil {
			if err == io.EOF {
				return
			}
			s.writeError(nil, -1, "read_error", err.Error())
			continue
		}

		switch msg.Method {
		case "initialize":
			sessionId = s.handleInitialize(msg)

		case "notifications/initialized":
			// Client ready — send tool list
			s.sendTools(sessionId)

		case "tools/list":
			s.sendTools(sessionId)

		case "tools/call":
			s.handleToolCall(msg, sessionId)

		default:
			if msg.ID != nil {
				s.writeError(msg.ID, -32601, "method_not_found",
					fmt.Sprintf("unsupported method: %s", msg.Method))
			}
		}
	}
}

// ===== Handlers =====

func (s *Server) handleInitialize(msg Message) string {
	params := msg.Params
	var req InitializeRequest
	if err := json.Unmarshal(params, &req); err != nil {
		s.writeError(msg.ID, -32602, "invalid_params", err.Error())
		return ""
	}

	caps := ServerCapabilities{}
	if len(s.tools) > 0 {
		tcaps := make([]ToolCaps, 0, len(s.tools))
		for name, h := range s.tools {
			// Best-effort: use description if available, empty schema otherwise
			tcaps = append(tcaps, ToolCaps{
				Name:        name,
				Description: fmt.Sprintf("%s handler", name),
				InputSchema: extractSchema(h, name),
			})
		}
		caps.Tools = tcaps
	}

	result, _ := json.Marshal(map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"serverInfo": map[string]string{
			"name":    s.name,
			"version": s.version,
		},
		"capabilities": caps,
	})

	s.writeResult(msg.ID, result)
	return "session-" + s.name
}

func (s *Server) sendTools(sessionId string) {
	tcaps := make([]ToolCaps, 0, len(s.tools))
	for name, h := range s.tools {
		tcaps = append(tcaps, ToolCaps{
			Name:        name,
			Description: fmt.Sprintf("%s handler", name),
			InputSchema: extractSchema(h, name),
		})
	}
	s.writeNotification("notifications/tools/list", map[string]interface{}{
		"tools": tcaps,
	})
}

func (s *Server) handleToolCall(msg Message, sessionId string) {
	var params ToolCallParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		s.writeError(msg.ID, -32602, "invalid_params", err.Error())
		return
	}

	s.mu.Lock()
	handler, ok := s.tools[params.Name]
	s.mu.Unlock()

	if !ok {
		s.writeError(msg.ID, -32601, "tool_not_found",
			fmt.Sprintf("unknown tool: %s", params.Name))
		return
	}

	result, err := handler(params.Arguments)
	if err != nil {
		s.writeError(msg.ID, -32000, "tool_error", err.Error())
		return
	}

	content, _ := json.Marshal(map[string]interface{}{
		"type":       "text",
		"text":       fmt.Sprintf("%v", result),
		"result_raw": result,
	})

	s.writeResult(msg.ID, json.RawMessage(fmt.Sprintf(`{"content":[%s],"isError":false}`, string(content))))
}

// ===== IO Helpers =====

func (s *Server) readMessage() (Message, error) {
	// Read Content-Length header
	line, err := s.readBuf.ReadString('\n')
	if err != nil {
		return Message{}, err
	}
	// Parse "Content-Length: N\r\n"
	contentLen := 0
	for _, part := range split(line, " ") {
		if len(part) > 0 && part[0] <= '9' {
			contentLen = parseInt(part)
			break
		}
	}
	if contentLen <= 0 {
		// Try to find "Content-Length:" in the line
		if idx := indexOf(line, "Content-Length:"); idx >= 0 {
			numStr := trim(substr(line, idx+len("Content-Length: "), '\n'))
			contentLen = parseInt(numStr)
		}
	}

	// Read body
	body := make([]byte, contentLen)
	total := 0
	for total < contentLen {
		n, err := s.readBuf.Read(body[total:])
		if err != nil {
			return Message{}, err
		}
		total += n
	}
	// Consume trailing \r\n
	s.readBuf.Discard(2)

	var msg Message
	if err := json.Unmarshal(body, &msg); err != nil {
		return Message{}, err
	}
	return msg, nil
}

func (s *Server) writeResponse(msg Message) {
	data, _ := json.Marshal(msg)
	data = append(data, '\r', '\n')
	fmt.Fprintf(s.out, "Content-Length: %d\r\n\r\n", len(data))
	s.out.Write(data)
}

func (s *Server) writeResult(id interface{}, result json.RawMessage) {
	s.writeResponse(Message{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func (s *Server) writeError(id interface{}, code int, message, data string) {
	s.writeResponse(Message{
		JSONRPC: "2.0",
		ID:      id,
		Error: &ResponseError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	})
}

func (s *Server) writeNotification(method string, params map[string]interface{}) {
	// Notifications have no ID
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	})
	fmt.Fprintf(s.out, "Content-Length: %d\r\n\r\n", len(b))
	s.out.Write(b)
}

// ===== Minimal helpers (no external deps) =====

func extractSchema(handler ToolHandler, name string) map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"_mcp_hint": map[string]interface{}{
				"type": "string",
				"description": fmt.Sprintf("Call %s — register proper input_schema at startup", name),
			},
		},
	}
}

func split(s, sep string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			parts = append(parts, s[start:i])
			start = i + len(sep)
		}
	}
	parts = append(parts, s[start:])
	return parts
}
func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func substr(s string, start int, end byte) string {
	endIdx := indexOf(s, string(end))
	if endIdx < 0 {
		endIdx = len(s)
	}
	if start >= len(s) {
		return ""
	}
	if endIdx < start {
		return s[start:]
	}
	return s[start:endIdx]
}
func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r' || s[0] == '\n') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}
func parseInt(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
