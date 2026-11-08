// Package config loads and hot-reloads gateway configuration.
type Config struct {
	Cloud   CloudCfg     `json:"cloud"`
	Security SecurityCfg `json:"security"`
	Users   []User      `json:"users"`
	Tenants TenantsCfg  `json:"tenants"`
	MCP     MCPCfg      `json:"mcp"`
	Paths   PathCfg     `json:"paths"`
	Modules map[string]bool `json:"modules"`
	CustomTools []CustomTool `json:"customTools"`
	CustomAgents []CustomAgent `json:"customAgents"`
	Direct DirectCfg `json:"direct"`
	OAuth OAuthCfg `json:"oauth"`
	Gatekeeper GatekeeperCfg `json:"gatekeeper"`
	Audit AuditCfg `json:"audit"`
	Persona PersonaCfg `json:"persona"`
	ModelAliases []ModelAlias `json:"modelAliases"`
	InstallRoot string `json:"installRoot"`
	DataRoot    string `json:"dataRoot"`
}

type CloudCfg struct {
	OpenAI   ProviderEntry `json:"openai"`
	DeepSeek ProviderEntry `json:"deepseek"`
	Custom   []ProviderEntry `json:"custom"`
}

type ProviderEntry struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
	Models  []string `json:"models"`
	Active  bool   `json:"active"`
}

type SecurityCfg struct {
	WAFEnabled    bool   `json:"waf_enabled"`
	Mode          string `json:"mode"` // "normal" | "strict"
	APIKey        string `json:"apiKey"`
	AuditLogEnabled bool `json:"audit_log_enabled"`
	Firewall      FirewallCfg `json:"firewall"`
	DefaultKeyAllowed *bool `json:"defaultKeyAllowed"`
	PIIMaskEnabled bool `json:"piimask_enabled"`
	PIIMaskLevel   string `json:"piimask_level"` // "full" | "partial" | "hash"
}

type FirewallCfg struct {
	Policy      string `json:"policy"`      // "passive" | "dynamic-ban" | "os-link"
	BanDuration string `json:"banDuration"` // duration string, e.g. "10m"
}

type User struct {
	Name    string   `json:"name"`
	APIKey  string   `json:"apiKey"`
	Role    string   `json:"role"`    // admin | user | readonly | team_lead | auditor | global_admin | global_auditor
	Tenant  string   `json:"tenant"`
	Groups  []string `json:"groups"`
	Enabled bool     `json:"enabled"`
}

type TenantsCfg struct {
	Enabled bool   `json:"enabled"`
	DefaultQuota int `json:"default_quota"`
}

type MCPCfg struct {
	ExternalServers []ExtServer `json:"externalServers"`
}

type ExtServer struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Protocol string `json:"protocol"` // "stdio" | "sse" | "http"
	Command string `json:"command,omitempty"`
	Args []string `json:"args,omitempty"`
	Env map[string]string `json:"env,omitempty"`
}

type PathCfg struct {
	ModelDir     string   `json:"modelDir"`
	LlamaDir     string   `json:"llamaDir"`
	AllowedRoots []string `json:"allowedRoots"`
}

type CustomTool struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Url          string                 `json:"url"`
	Method       string                 `json:"method"` // GET | POST | PUT | DELETE
	Headers      map[string]string      `json:"headers"`
	Body         map[string]interface{} `json:"body"`
	SSRFProtected bool                  `json:"ssrf_protected"` // true = uses ssrfGuardedClient
}

type CustomAgent struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Prompt string `json:"prompt"`
	Model  string `json:"model"` // model ID to use; empty = auto
}

type DirectCfg struct {
	Transport string `json:"transport"` // "native" | "grpc-sidecar"
	GRPCSidecar struct {
		Address string `json:"address"` // 127.0.0.1 or unix socket only
	} `json:"grpcSidecar"`
}

type OAuthCfg struct {
	Enabled     bool     `json:"enabled"`
	ClientID    string   `json:"client_id"`
	ClientSecret string  `json:"client_secret"`
	Scopes      []string `json:"scopes"`
	Issuer      string   `json:"issuer"`
}

type GatekeeperCfg struct {
	Enabled bool     `json:"enabled"` // default true
	Rules   []GKRule `json:"rules"`
}

type GKRule struct {
	Tools       []string `json:"tools"`
	Action      string   `json:"action"` // "deny" | "confirm" | "allow"
	Description string   `json:"description"`
}

type AuditCfg struct {
	Enabled     bool   `json:"enabled"` // default true
	LogFile     string `json:"log_file"`
	RotateSizeMB int   `json:"rotate_size_mb"` // default 100
	RetainDays   int   `json:"retain_days"`    // default 90
}

type PersonaCfg struct {
	Default string `json:"default"` // "student" | "writer" | "developer" | "researcher" | "general"
}

type ModelAlias struct {
	Alias    string `json:"alias"`
	Target   string `json:"target"`
}

// ===== Loaders =====

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return &defaultConfig(), err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return &defaultConfig(), err
	}
	// Apply defaults for missing fields
	ensureDefaults(&cfg)
	return &cfg, nil
}

func (c *Config) Save() error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := c.Path() + ".tmp"
	if err := os.WriteFile(tmpPath, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, c.Path())
}

// Ensure waf mode is valid
func ensureDefaults(cfg *Config) {
	if cfg.Security.Mode == "" {
		cfg.Security.Mode = "normal"
	}
	if cfg.Security.WAFEnabled {
		// WAF cannot be disabled in security-core
	}
	if cfg.Audit.Enabled {
		// default audit log path
	}
	for _, u := range cfg.Users {
		if u.Role == "" {
			u.Role = "user"
		}
	}
}

func defaultConfig() Config {
	return Config{
		Security: SecurityCfg{
			WAFEnabled: true,
			Mode:       "normal",
			APIKey:     "tars-gateway-key",
			AuditLogEnabled: true,
			DefaultKeyAllowed: boolPtr(false), // [ZT_DEFAULT_DENY]
			PIIMaskEnabled: true,
			PIIMaskLevel: "full",
		},
		Paths: PathCfg{
			AllowedRoots: []string{"/app", "/home", "/tmp"},
		},
		Modules: map[string]bool{
			"chatApi": true, "localModels": true, "cloudModels": true,
			"builtinTools": true, "memory": true,
		},
	}
}

func boolPtr(v bool) *bool { return &v }
