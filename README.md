# TarsCore 2.0 — Enterprise-Grade Unified AI Security Gateway

> **Architecture Inspired by:** Tencent NT Architecture · Alibaba Sentinel Flow Governance · ByteDance Middle Platform Thinking · Cloud-Native Academic Best Practices

## 🚀 Quick Start

### Prerequisites
- Go 1.22+
- Docker (optional for containerized deployment)
- Git

### Install from Source

```bash
git clone https://github.com/HP-jh/TarsCore.git
cd TarsCore
go build ./cmd/tars-core
./tarscore              # First-time setup wizard will launch
```

### Docker Deployment

```bash
docker-compose up -d   # or use kubernetes manifests in deploy/kubernetes/
```

### Configuration

First run launches an interactive wizard. For advanced users, create `~/.tarscore/config.json`:

```json
{
  "port": 18889,
  "metrics_port": 9090,
  "model_dir": "/models",
  "llama_dir": "/usr/local/bin",
  "security": {
    "waf_enabled": true,
    "mode": "normal",
    "max_body_bytes": 5242880,
    "gatekeeper_rules": [],
    "oauth": {
      "enabled": false,
      "google_client_id": "",
      "google_client_secret": ""
    }
  },
  "traffic": {
    "global_qps": 1000,
    "policy": "sliding-window"
  },
  "i18n": {
    "default_language": "zh",
    "supported_languages": ["zh", "en", "ja", "ko", "ru", "ar"]
  },
  "logging": {
    "level": "info",
    "format": "json"
  },
  "modules": {}
}
```

## 🏗️ Architecture Overview

TarsCore implements a four-layer enterprise architecture inspired by Tencent's NT (New Technology) Architecture:

```
┌─────────────────────────────────────────────────────┐
│              接入层 (Ingress Layer)                  │
│  HTTP/WebSocket/SSE → SSL Termination → Rate Limit  │
│  WAF Gate → Auth/N → RBAC Authorization             │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│              业务层 (Business Layer)                 │
│  Smart Router → Model Manager → Tool Executor       │
│  Circuit Breaker → Traffic Governor → Fallback      │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│              数据层 (Data Layer)                     │
│  Provider Registry → Model Cache → Session Store    │
│  Shared Memory → Context Builder                    │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│           基础设施层 (Infrastructure Layer)          │
│  Container Orchestration (K8s)                      │
│  Monitoring Stack (Prometheus/Grafana/OpenTelemetry)│
│  Distributed Tracing + Structured Logging            │
└─────────────────────────────────────────────────────┘
```

## 🔐 Security Modules

### WAF Engine (Web Application Firewall)
- **Path Traversal Detection**: `../`, `%2e%2e`, UTF-8 encoded variants
- **Command Injection Prevention**: Shell metacharacters + command whitelisting
- **SQL Injection Rules**: UNION SELECT, DROP TABLE, SLEEP patterns
- **XSS Protection**: Script injection, event handlers, iframe attacks
- **Prompt Injection Defense**: Jailbreak patterns, DAN mode, system prompt extraction
- **PII Leak Prevention**: Credit cards, SSNs, email patterns, phone numbers
- **Scanner UA Blacklist**: sqlmap, nikto, nmap, burpsuite, nuclei detection
- **Sensitive Path Probing**: `.env`, `.git`, `wp-admin`, `phpmyadmin` blocks
- **Header Injection**: CRLF/null byte protection for Host and all headers
- **HTTP Smuggling**: CL+TE double-header attack detection
- **Performance Optimized**: Merged regex, ASCII trigger-byte pre-skip, UA caching

### Gatekeeper (Two-Phase Confirm Mechanism)
High-risk tool executions require explicit confirmation:
- **Deny**: Automatic rejection for `.ssh/`, `.env`, `.git/config`, security configs
- **Confirm**: Token-based approval for model start/stop/download, large file writes
- **Token Binding**: Cryptographic binding of user+tool+argument hash
- **Rate Limiting**: Max 20 confirm requests/min per user, max 10 pending

### SSRF Protection Factory
- **Connection-Time IP Validation**: Reject loopback, RFC1918, link-local, multicast
- **DNS Rebinding Defense**: Verified IP used directly for dial
- **Redirect-by-Redirect Validation**: Every 3xx hop re-checked
- **Protocol Whitelist**: Only HTTP/HTTPS allowed
- **Dual Client Pools**: Guarded for user-controlled URLs; exception pool for fixed endpoints

### Semantic Guard
- **Static Deny List**: Prompt injection patterns always blocked
- **Static Allow List**: Common greetings fast-path skipped
- **Grey Zone Engine**: Local small-model classification with fail-close iron rule
- **AI Can Only Tighten**: Static block cannot be relaxed by any AI verdict
- **Per-IP Quota**: 5 grey-zone requests/minute/IP
- **Fingerprint Caching**: SHA-256 text fingerprint avoids redundant engine calls

### RBAC Authentication & Authorization
- **API Key Authentication**: Header, Bearer token, or query param
- **7-Role Hierarchy**: global_admin > admin > global_auditor > auditor > team_lead > user > readonly
- **Resource-Class Permissions**: admin-read/write, app-read/write
- **Zero-Trust Default**: Default API key disabled unless explicitly enabled

## ⚡ Traffic Governance Engine

Inspired by Alibaba Sentinel's distributed flow control:

### Sliding Window Counter (QPS Limiter)
- Precise request counting with configurable window size and bucket count
- O(1) amortized complexity per request
- Configurable interval subdivision for fine-grained control

### Token Bucket Algorithm
- Constant throughput guarantee regardless of input burstiness
- Configurable refill rate and maximum token capacity
- Non-blocking wait with context timeout support

### Leaky Bucket Algorithm
- Constant output rate smoothing
- Prevents sudden traffic spikes from overwhelming downstream services
- Water level monitoring and auto-drain

### Adaptive System Overload Protection
- CPU/Memory-driven dynamic limit adjustment
- Exponential backoff on system stress
- Graceful degradation with minimum service threshold

### Hotspot Parameter Rate Limiting
- Per-parameter-value limits (e.g., per-user, per-API-key)
- Automatic creation and cleanup of parameter-specific limiters
- Configurable fallback for unknown parameters

## 🧠 Intelligent Routing

Two-stage smart router combining deterministic rules with ML-inspired bandit optimization:

### Stage 1: Deterministic Static Rules
- Prefix matching (`ollama/`, `lmstudio/`, `llama/`)
- Health-check based backend availability
- Fast path for known providers

### Stage 2: ε-Greedy Bandit Optimization
- Epsilon decays from 0.1 → 0.02 over time
- Reward function: `1/(1 + latency_seconds)` for success, `-1` for failure
- Non-admin feedback weighted at ×0.1 to prevent manipulation
- Cold-start prior of 0.5 encourages exploration
- State persistence survives restarts

### Circuit Breaker Pattern
- Three states: Closed → Open → Half-Open
- Per-provider tracking with configurable thresholds
- Probe requests during half-open recovery phase
- Audit trail for all state transitions

## 🎯 Platform Capability Center

Inspired by ByteDance's middle-platform thinking — reusable, composable services:

### Model Lifecycle Manager
- Auto-discovery of local models (GGUF/Ollama/LMStudio)
- Seamless chat routing across all providers
- Health checks and automatic failover
- Model download progress tracking

### MCP Server Implementation
- Full JSON-RPC stdio protocol support
- Dynamic tool registration and discovery
- tools/list and tools/call method handling
- Content-type negotiation and error formatting

### Tool Registry Framework
- Schema-driven tool definition
- Async handler pattern with execution audit trail
- Module-gated execution permissions
- History tracking for every call

### Shared Memory System
- Cross-session KV storage for persistent data
- Namespace isolation for multi-tenant environments
- Automatic cleanup and TTL management

### Context Builder
- Budget-aware context assembly
- Token-aware chunk management
- Multi-source content fusion
- Reset and rebuild capabilities

## 🌍 Internationalization Engine

Six-language support with real-time translation:
- Chinese Simplified (zh), English (en), Japanese (ja), Korean (ko), Russian (ru), Arabic (ar)
- Language detection from content
- Resource bundle loading with validation
- Hook system for custom translations

## 👁️ Observability Stack

Enterprise-grade monitoring following the three pillars:

### Metrics
- Prometheus-compatible counters, gauges, histograms
- Request rate, error rate, latency distribution
- Custom business metrics with labels

### Distributed Tracing
- OpenTelemetry-compatible span propagation
- Trace ID injection across all HTTP boundaries
- Latency attribution per middleware layer
- Error correlation via trace context

### Structured Logging
- Log levels: DEBUG, INFO, WARN, ERROR, FATAL
- JSON format for ELK stack compatibility
- Field-based filtering and sampling
- File and console dual-output support

### Smart Alerting
- Rule-based alerting with multiple operators (gt, lt, eq)
- Minimum violation threshold before firing
- Automatic resolution detection
- Configurable alert history retention

## 📂 Directory Structure

```
TarsCore/
├── cmd/tarscore/        # Main CLI entry point + Interactive wizard
├── pkg/                 # Public libraries (zero import cycles)
│   ├── core/            # Engine framework + lifecycle management
│   ├── security/        # Security matrix (WAF/Gatekeeper/SSRF/Semantic/Auth)
│   ├── traffic/         # Flow control engine (Sentinel-style)
│   ├── observability/   # Metrics/Tracing/Logging/Alerting
│   ├── gateway/         # HTTP server + middleware chain + dashboard
│   ├── platform/        # Model manager + tool registry + memory + i18n
│   └── module/          # Feature-flag framework + dependency topology
├── frontend/static/     # React-style SPA dashboard
├── deploy/              # Docker + Kubernetes + Terraform IaC
├── docs/                # Comprehensive documentation
├── tests/               # Unit + Integration + E2E test suites
└── web/                 # Frontend React components (optional)
```

## 🔌 Adapter Ecosystem

TarsCore integrates with your existing projects through standardized MCP adapters:

| Adapter | Purpose | Status |
|---------|---------|--------|
| Dify | LLM application platform bridge | ✅ Implemented |
| LiteLLM | Unified LLM interface (100+ providers) | ✅ Implemented |
| RAGFlow | Knowledge base retrieval enhancement | ✅ Implemented |
| LangChain | Agent orchestration framework | ✅ Implemented |
| N8N | Workflow automation platform | 🔄 Coming Soon |
| AutoGPT | Autonomous agent platform | 🔄 Coming Soon |
| UI-TARS | Desktop GUI agent bridge | 🔄 Coming Soon |

## 🔧 Development Guide

### Adding a New Module

1. Create package under `pkg/<name>/`
2. Implement `Module` interface:
   ```go
   type Module interface {
       Name() string
       Start(ctx context.Context) error
       Stop(ctx context.Context) error
       IsHealthy() bool
   }
   ```
3. Register with engine: `engine.RegisterModule(&MyModule{})`

### Using the Traffic Control API

```go
// Create sliding window limiter
limiter := traffic.NewSlidingWindow(maxRPS, windowSize, intervals)

// Check if request can proceed
if limiter.Allow() {
    // Process request
} else {
    // Reject or queue
}

// Adaptive overload protection
adaptive := traffic.NewAdaptiveLimiter(baseLimit)
adaptive.Allow() // Automatically adjusts based on CPU/memory load
```

### Integrating With External Providers

```go
mgr := platform.NewModelManager(modelDir, llamaDir)
mgr.RegisterProvider(provider) // Any provider implementing Provider interface

result, err := mgr.Chat(platform.ChatRequest{
    Model: "openai/gpt-4",
    Messages: []platform.Message{
        {Role: "user", Content: "Hello!"},
    },
})
```

## 🚦 Roadmap

- [x] Enterprise architecture framework (Tencent NT inspired)
- [x] Traffic governance engine (Alibaba Sentinel style)
- [x] Observability stack (Metrics/Tracing/Logging)
- [x] Interactive first-time setup wizard
- [x] Multi-language i18n support
- [x] Reactive Dashboard UI
- [ ] K8s operator for automated deployment
- [ ] WASM plugin system for custom modules
- [ ] Federated learning gateway for privacy-preserving AI
- [ ] Real-time threat intelligence integration

## 📄 License

MIT License — see LICENSE file for details.

---

**Built with ❤️ for the AI security community.**  
For issues and contributions, please open an issue on GitHub.
