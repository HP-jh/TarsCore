# TarsCore

**Unified AI Security Gateway — modular, zero-dependency, local-first.**

Built from [TarsSecureGuard](https://github.com/HP-jh/TarsSecureGuard) with enterprise-grade architecture inspired by Tencent's microservice design principles. Every security feature is a standalone, swappable module. The gateway ships as a single binary with zero external dependencies.

## Architecture

```
                    ┌──────────────┐
    Client ◄───────►│  TarsCore   │◄── MCP Clients (Dify/LiteLLM/RAGFlow/…)
                    │  Gateway     │
                    └───┬───┬───┬──┘
                         │   │   │
              ┌──────────┘   │   └──────────┐
              ▼              ▼               ▼
       ┌───────────┐  ┌───────────┐  ┌───────────┐
       │ WAF Engine│  │ Router    │  │ Tool      │
       │(6 rules,  │  │(static +  │  │ Registry  │
       │ merged RE)│  │  bandit)  │  │           │
       └───────────┘  └───────────┘  └───────────┘
              │               │               │
       ┌───────────┐  ┌───────────┐  ┌───────────┐
       │Gatekeeper │  │Circuit    │  │ MCP       │
       │(2-phase   │  │ Breaker   │  │ Server    │
       │  confirm) │  │(3-state)  │  │           │
       └───────────┘  └───────────┘  └───────────┘
```

### Module Layer

| Module | Category | Description | Toggle |
|--------|----------|-------------|--------|
| `chatApi` | core | OpenAI-compatible `/v1` chat completions | ✅ default |
| `localModels` | models | GGUF / Ollama / LMStudio detection & lifecycle | ✅ default |
| `cloudModels` | models | OpenAI / DeepSeek / custom provider routing | ✅ default |
| `builtinTools` | tools | File, search, fetch, system info tools | ✅ default |
| `mcpExternal` | tools | External MCP stdio server bridge | ✅ default |
| `webSearch` | tools | Bing RSS + Serper search | ✅ default |
| `webFetch` | tools | URL-to-text converter | ✅ default |
| `semanticGuard` | security | Static deny + grey-zone engine (fail-close) | ✅ default |
| `smartRouter` | ops | Two-stage: static rules + ε-greedy bandit | ✅ default |
| `resourceGuardian` | ops | GOMEMLIMIT soft limit + eco mode | ✅ default |
| `persona` | core | Career presets with auto-config | ✅ default |
| `observability` | ops | Prometheus metrics + trace/span timeline | ✅ default |
| `sidecarHub` | tools | Ex-module host with SHA-256 pinning | ✅ default |
| `contextGov` | core | Shared KV memory + context budget injection | ✅ default |
| `security-core` | security | **FORCED — cannot toggle off** | 🔒 locked |

## Quick Start

### Build

```bash
go build ./cmd/tars-core
```

### Run

```bash
./tars-core          # starts on http://127.0.0.1:18889
./tars-core --port 8080  # custom port
./tars-core mcp-stdio    # MCP stdio mode (for agent frameworks)
./tars-core doctor       # self-diagnostic
```

### Configuration

Place `~/.tarscore/config.json`:

```json
{
  "cloud": {
    "openai": {
      "base_url": "https://api.openai.com/v1",
      "api_key": "sk-..."
    },
    "deepseek": {
      "base_url": "https://api.deepseek.com/v1",
      "api_key": "sk-..."
    }
  },
  "security": {
    "waf_enabled": true,
    "mode": "normal",
    "apiKey": "your-secret-key",
    "audit_log_enabled": true,
    "firewall": {
      "policy": "passive",
      "banDuration": "10m"
    }
  },
  "paths": {
    "modelDir": "/models",
    "llamaDir": "/usr/local/bin",
    "allowedRoots": ["/app", "/home"]
  },
  "users": [
    {
      "name": "admin",
      "apiKey": "supersecretkey",
      "role": "global_admin",
      "enabled": true
    }
  ],
  "modules": {
    "chatApi": true,
    "localModels": true,
    "semanticGuard": true
  }
}
```

## Modules & Adapters

TarsCore exposes an ecosystem of adapters that integrate your existing projects into the unified gateway:

| Adapter | Source Repo | Purpose |
|---------|-------------|---------|
| Dify | `TarsDify` | MCP adapter for Dify LLM app platform |
| LiteLLM | `TarsLiteLLM` | MCP adapter for LiteLLM (100+ LLMs) |
| RAGFlow | `TarsRAGFlow` | MCP adapter for open-source RAG engine |
| LangChain | `TarsLangChain` | MCP adapter for LangChain orchestration |
| N8N | `TarsN8N` | MCP adapter for workflow automation |
| AutoGPT | `TarsAutoGPT` | MCP adapter for autonomous agents |
| UI-TARS | `TarsUITarsBridge` | Desktop GUI agent bridge |
| Bifrost | `TarsBifrost` | MCP adapter for Maxim AI routing |
| OneAPI | `TarsOneAPI` | MCP adapter for multi-model gateway |
| Portkey | `TarsPortkey` | MCP adapter with observability |
| Higress | `TarsHigress` | MCP adapter for cloud-native API gateway |

Each adapter is independently deployable and connects to TarsCore via MCP stdio or SSE protocol.

## Security Features

### WAF (Web Application Firewall)
- **Path traversal** detection (`../`, `%2e%2e`, UTF-8 encoded variants)
- **Command injection** detection (shell metacharacters + common commands)
- **SQL injection** (UNION SELECT, DROP TABLE, SLEEP, etc.) — strict mode only
- **XSS** (script tags, event handlers, iframe injection) — strict mode only
- **Prompt injection** (jailbreak patterns, DAN mode, developer mode bypasses) — strict mode only
- **PII leak prevention** (credit cards, SSNs, emails, phone numbers) — strict mode only
- **Scanner UA blacklist** (sqlmap, nikto, nmap, burpsuite, nuclei, etc.)
- **Sensitive path probing** (.env, .git, wp-admin, phpmyadmin, etc.)
- **Header injection protection** (CRLF/null bytes in Host and all headers)
- **HTTP smuggling detection** (CL+TE double-header attack)
- **Performance optimized**: merged regex, ASCII trigger-byte pre-skip, scanner UA cache

### Gatekeeper (Two-Phase Confirmation)
High-risk tool executions require explicit confirmation:
- **Deny**: writing to `.ssh/`, `.env`, `.git/config`, security-critical config paths — automatic rejection
- **Confirm**: model start/stop/download, large file writes (>1MB), config changes — requires token-based approval
- **Token binding**: tokens bind user + tool + argument hash; tampering invalidates them
- **Rate limiting**: max 20 confirm requests per minute per user; max 10 pending at a time
- **Config rules can only tighten** — never loosen built-in security decisions

### SSRF Protection
- Connection-time IP validation (reject loopback, RFC1918, link-local, multicast, unspecified)
- DNS rebinding defense: verified IP used directly for dial (not hostname)
- Redirect-by-redirect validation: every 3xx hop re-checked against whitelist + IP rules
- Protocol whitelist: only HTTP/HTTPS allowed
- Separate client pools: guarded for user-controlled URLs; exception pool for fixed endpoints (Ollama/LMStudio on localhost)

### Semantic Guard
- **Static deny list**: prompt injection patterns, jailbreak keywords — always block
- **Static allow list**: common greetings/short phrases — fast-path skip
- **Grey zone**: remaining text sent to local small-model engine (0.5B–1.5B parameters)
- **Fail-close**: if engine is unavailable → block; no grey-zone request passes
- **Iron rule**: AI verdict can only tighten, never relax static block results
- **Per-IP rate limiting**: 5 grey-zone requests per minute per IP
- **Fingerprint caching**: SHA-256 fingerprint of normalized text avoids redundant engine calls

### Smart Router
- **Stage 1**: deterministic static rules (prefix matching → ollama/, lmstudio/, llama/)
- **Stage 2**: ε-greedy bandit optimizes auto-selection when multiple backends reachable
  - Epsilon decays from 0.1 → 0.02 over time
  - Reward function: `1/(1 + latency_seconds)` for success, `-1` for failure
  - Non-admin feedback weighted at ×0.1 to prevent manipulation
- **State persistence**: saves to disk every 60 seconds; survives restarts

### Circuit Breaker
- Three states: closed → open → half-open
- Per-provider tracking (5 consecutive failures → 30s open → probe on cooldown expiry)
- Half-open test: one probe request determines recovery vs re-trip
- Logs state transitions for audit trail

### Authentication & RBAC
- API Key authentication (header, Bearer token, or query param)
- Role hierarchy: `global_admin > admin > global_auditor > auditor > team_lead > user > readonly`
- Resource-class permissions: admin-read/write, app-read/write
- Zero-trust default: default key (`tars-gateway-key`) disabled unless explicitly enabled

## Directory Structure

```
TarsCore/
├── cmd/tars-core/         # Main entry point
│   └── main.go            # CLI subcommands, server bootstrap
├── pkg/                   # Public libraries (zero import cycles)
│   ├── auth/rbac/         # User roles + permission matrices
│   ├── config/            # JSON config loader + hot-reload watcher
│   ├── health/circuit/    # Three-state circuit breaker
│   ├── i18n/              # Six-language translation engine
│   ├── media/             # Image/video/audio processing pipeline
│   ├── memory/shared/     # Shared KV memory across sessions
│   ├── mcp/server/        # MCP stdio server implementation
│   ├── models/            # Local model management + provider registry
│   │   ├── manager.go     # GGUF/Ollama/LMStudio detection & lifecycle
│   │   └── providers/     # Cloud provider definitions
│   ├── module/            # Feature-flag framework with dependency topology
│   ├── observability/     # Prometheus metrics + trace/span recording
│   ├── router/            # Two-stage smart router (static + bandit)
│   ├── security/          # Core security modules (all swappable)
│   │   ├── waf/           # Web application firewall engine
│   │   ├── ssrf/          # SSRF prevention factory
│   │   ├── semantic/      # Semantic classification engine
│   │   ├── gatekeeper/    # Two-phase confirm mechanism
│   │   └── middleware/    # HTTP middleware chain
│   └── tools/             # Tool registry + execution framework
├── internal/              # Private implementation details
│   ├── core/              # Internal gateway logic
│   ├── meta/              # Build metadata
│   └── tlsconfig/         # TLS configuration helpers
├── frontend/static/       # Web dashboard assets
├── config/                # Example configs
├── docs/                  # Documentation
├── scripts/               # Build/deploy helpers
├── tests/                 # Integration test fixtures
├── deploy/docker/         # Dockerfile + docker-compose
├── .github/workflows/     # CI/CD pipelines
└── go.mod
```

## Development

### Adding a New Module

1. Create `pkg/<module_name>/` with package-level code
2. Register in `pkg/module/registry.go`'s `registry` slice:
   ```go
   {ID: "myModule", Name: "My Module", Description: "...", Category: "tools", Default: true}
   ```
3. If it has a background worker, add a `HasWorker: true` flag and implement `startMyModule(ctx context.Context)`
4. Route endpoints through `moduleRoute("myModule", handler)` to respect the toggle

### Adding a New Provider

1. Add to `providers/*.json` files under `pkg/models/providers/`
2. Or call `Add()` at startup with a `Provider` struct
3. The circuit breaker worker will auto-probe health for any configured provider

### Tool Registration

```go
toolReg.Register(
    "my_tool",                          // tool name
    "What this tool does",             // description
    schema,                             // JSON Schema input
    func(args map[string]interface{}) (interface{}, error) {
        return myLogic(args)
    },                                  // handler
    "builtinTools",                     // gating module
)
```

### Config Hot-Reload

The gateway watches `config.json` for changes. On modification:
1. Parses new config
2. Applies module dependency closure (auto-enables/disables dependent modules)
3. Reconciles background workers (stops/stops based on new states)
4. Effectively live within ~2 seconds

## License

MIT — See [LICENSE](./LICENSE) for details.

## Changelog

See [CHANGELOG.md](https://github.com/HP-jh/TarsSecureGuard/blob/main/CHANGELOG.md) for full release history. This project evolved from TarsSecureGuard v4.x through extensive security hardening iterations.
