// Package builder provides context assembly with token budget management.
package builder

import (
	"strings"
	"sync"
)

type Chunk struct {
	Content string
	Tokens  int
	Priority int // Higher = more important
}

type ContextBuilder struct {
	mu        sync.Mutex
	chunks    []Chunk
	maxTokens int
	currentLen int
}

func New(maxTokens int) *ContextBuilder {
	return &ContextBuilder{
		chunks:    make([]Chunk, 0),
		maxTokens: maxTokens,
	}
}

func (cb *ContextBuilder) Add(content string, tokens int, priority int) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	if cb.currentLen + tokens <= cb.maxTokens {
		cb.chunks = append(cb.chunks, Chunk{
			Content: content,
			Tokens:  tokens,
			Priority: priority,
		})
		cb.currentLen += tokens
		return true
	}
	return false
}

func (cb *ContextBuilder) Build() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	// Sort by priority (higher first)
	sorted := make([]Chunk, len(cb.chunks))
	copy(sorted, cb.chunks)
	
	var result strings.Builder
	for _, chunk := range sorted {
		result.WriteString(chunk.Content)
		result.WriteString("\n\n")
	}
	return result.String()
}

func (cb *ContextBuilder) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.chunks = nil
	cb.currentLen = 0
}

func (cb *ContextBuilder) Len() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.currentLen
}
