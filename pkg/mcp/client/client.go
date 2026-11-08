// Package client implements the MCP client for connecting to external MCP servers.
package mcpclient

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

type Server struct {
	Name   string
	StdCmd *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	mu     sync.Mutex
}

func New(name, cmdStr string, args []string) *Server {
	cmd := exec.Command(cmdStr, args...)
	
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Printf("[MCP] Failed to create stdin pipe for %s: %v\n", name, err)
		return nil
	}
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		fmt.Printf("[MCP] Failed to create stdout pipe for %s: %v\n", name, err)
		return nil
	}
	
	srv := &Server{Name: name, StdCmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout)}
	
	go srv.readLoop()
	
	if err := cmd.Start(); err != nil {
		stdin.Close()
		fmt.Printf("[MCP] Failed to start server %s: %v\n", name, err)
		return nil
	}
	
	fmt.Printf("[MCP] Started server: %s\n", name)
	return srv
}

func (s *Server) Close() {
	if s.stdin != nil {
		s.stdin.Close()
	}
	if s.StdCmd.Process != nil {
		s.StdCmd.Wait()
	}
}

func (s *Server) Send(msg map[string]interface{}) ([]byte, error) {
	data, _ := json.Marshal(msg)
	fmt.Fprintf(s.stdin, "Content-Length: %d\r\n\r\n", len(data))
	s.stdin.Write(data)
	return data, nil
}

func (s *Server) readLoop() {
	for {
		line, err := s.stdout.ReadString('\n')
		if err != nil {
			break
		}
		
		var contentLen int
		fmt.Sscanf(line, "Content-Length: %d", &contentLen)
		if contentLen <= 0 {
			continue
		}
		
		body := make([]byte, contentLen)
		io.ReadFull(s.stdout, body)
		
		s.mu.Lock()
		_ = body // process message
		s.mu.Unlock()
	}
}
