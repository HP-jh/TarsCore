package memory

import (
	"sync"
)

type ContextBuilder struct {
	mu        sync.Mutex
	chunks    []Chunk
	maxTokens int
	currentLen int
}

type Chunk struct {
	Content string
	Tokens  int
}

func NewContextBuilder(maxTokens int) *ContextBuilder {
	return &ContextBuilder{maxTokens: maxTokens}
}

func (cb *ContextBuilder) Add(content string, tokens int) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	if cb.currentLen + tokens <= cb.maxTokens {
		cb.chunks = append(cb.chunks, Chunk{Content: content, Tokens: tokens})
		cb.currentLen += tokens
	}
}

func (cb *ContextBuilder) Build() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	var result string
	for _, chunk := range cb.chunks {
		result += chunk.Content + "\n\n"
	}
	return result
}

func (cb *ContextBuilder) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.chunks = nil
	cb.currentLen = 0
}
