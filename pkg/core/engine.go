// Package core provides the TarsCore engine framework.
// It implements lifecycle management, context propagation, and plugin loading.
package core

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Engine is the main runtime controller for TarsCore.
// It manages initialization order, graceful shutdown, and cross-module communication.
type Engine struct {
	ctx       context.Context
	cancel    context.CancelFunc
	modules   []Module
	startTime time.Time
	config    *Config
	isRunning bool
}

// Module defines a pluggable component that can be loaded/unloaded at runtime.
type Module interface {
	Name() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	IsHealthy() bool
}

// Config holds the global configuration for the engine.
type Config struct {
	Port        int           `json:"port"`
	ModelDir    string        `json:"model_dir"`
	ConfigPath  string        `json:"config_path"`
	LogLevel    string        `json:"log_level"` // debug|info|warn|error
	LogFormat   string        `json:"log_format"` // json|console
	MetricsPort int           `json:"metrics_port"`
	Modules     map[string]bool `json:"modules"`
}

// New creates an initialized Engine instance.
func New(config *Config) *Engine {
	if config == nil {
		config = DefaultConfig()
	}
	if config.Port == 0 {
		config.Port = 18889
	}
	if config.MetricsPort == 0 {
		config.MetricsPort = 9090
	}
	if config.LogLevel == "" {
		config.LogLevel = "info"
	}
	return &Engine{
		config:    config,
		startTime: time.Now(),
	}
}

// DefaultConfig returns sensible defaults for all configuration fields.
func DefaultConfig() *Config {
	return &Config{
		Port:      18889,
		LogLevel:  "info",
		LogFormat: "json",
	}
}

// Use registers modules to be loaded in sequence during startup.
func (e *Engine) Use(modules ...Module) *Engine {
	e.modules = append(e.modules, modules...)
	return e
}

// Run starts all registered modules, sets up signal handlers, and blocks until shutdown.
func (e *Engine) Run() error {
	e.ctx, e.cancel = context.WithCancel(context.Background())
	e.isRunning = true

	// Signal handler for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[ENGINE] Received shutdown signal, stopping gracefully...")
		e.cancel()
	}()

	// Start each module in registration order
	for _, mod := range e.modules {
		fmt.Printf("[ENGINE] Starting module: %s\n", mod.Name())
		if err := mod.Start(e.ctx); err != nil {
			e.Stop()
			return fmt.Errorf("failed to start module %s: %w", mod.Name(), err)
		}
		fmt.Printf("[ENGINE] Module %s started successfully\n", mod.Name())
	}

	fmt.Printf("[ENGINE] TarsCore v%s running on port %d (metrics on %d)\n", 
		Version, e.config.Port, e.config.MetricsPort)

	// Block until context is cancelled
	<-e.ctx.Done()
	return e.Stop()
}

// Stop stops all modules in reverse order and cleans up resources.
func (e *Engine) Stop() error {
	if !e.isRunning {
		return nil
	}
	e.isRunning = false
	fmt.Println("[ENGINE] Stopping all modules...")

	for i := len(e.modules) - 1; i >= 0; i-- {
		mod := e.modules[i]
		fmt.Printf("[ENGINE] Stopping module: %s\n", mod.Name())
		shutdownCtx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
		if err := mod.Stop(shutdownCtx); err != nil {
			fmt.Printf("[WARN] Module %s stop failed: %v\n", mod.Name(), err)
		} else {
			fmt.Printf("[ENGINE] Module %s stopped cleanly\n", mod.Name())
		}
		cancel()
	}

	e.cancel()
	fmt.Printf("[ENGINE] All modules stopped. Uptime: %s\n", time.Since(e.startTime))
	return nil
}

// GetContext returns the engine's root context for use by modules.
func (e *Engine) GetContext() context.Context {
	return e.ctx
}

// IsRunning returns true if the engine is currently active.
func (e *Engine) IsRunning() bool {
	return e.isRunning
}
