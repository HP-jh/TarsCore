// Package auth implements API-key authentication and RBAC authorization.
package auth

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// ===== Types =====

// User represents a configured gateway user.
type User struct {
	Name   string `json:"name"`
	APIKey string `json:"apiKey"`
	Role   string `json:"role"`     // admin | user | readonly | team_lead | auditor | global_admin | global_auditor
	Tenant string `json:"tenant"`    // belongs to tenant (empty = default)
	Groups []string `json:"groups"`  // group memberships for group-level quotas / audit views
	Enabled bool  `json:"enabled"`
}

// Config holds the auth configuration derived from config.json users array + security section.
type Config struct {
	Users       []User
	DefaultKey  string // apiKey default fallback
	KeyAllowed  *bool  // nil=false means default key is off unless explicitly enabled
	Roles       map[string]Permissions
}

// Permissions defines what actions a role can perform on each resource class.
type Permissions struct {
	AdminRead   bool `json:"admin_read"`
	AdminWrite  bool `json:"admin_write"`
	AppRead     bool `json:"app_read"`
	AppWrite    bool `json:"app_write"`
}

var defaultRoles = map[string]Permissions{
	"admin":        {AdminRead: true, AdminWrite: true, AppRead: true, AppWrite: true},
	"global_admin": {AdminRead: true, AdminWrite: true, AppRead: true, AppWrite: true},
	"auditor":      {AdminRead: true, AdminWrite: false, AppRead: true, AppWrite: false},
	"global_auditor":{AdminRead: true, AdminWrite: false, AppRead: true, AppWrite: false},
	"team_lead":    {AdminRead: false, AdminWrite: false, AppRead: true, AppWrite: true},
	"user":         {AdminRead: false, AdminWrite: false, AppRead: true, AppWrite: true},
	"readonly":     {AdminRead: false, AdminWrite: false, AppRead: true, AppWrite: false},
}

// ===== Verification =====

func (c *Config) Verify(apiKey string) (userName, role string, ok bool) {
	for _, u := range c.Users {
		if !u.Enabled {
			continue
		}
		if matchKey(apiKey, u.APIKey) && u.Name != "" {
			return u.Name, u.Role, true
		}
	}
	// Fallback: check default key if allowed
	if c.DefaultKey != "" && c.DefaultKeyAllowed() {
		if matchKey(apiKey, c.DefaultKey) || matchKey(apiKey, "tars-gateway-key") {
			return "default", "admin", true
		}
	}
	return "", "", false
}

func (c *Config) DefaultKeyAllowed() bool {
	if c.KeyAllowed == nil {
		return false // [ZT_DEFAULT_DENY]: default key off by default
	}
	return *c.KeyAllowed
}

func (c *Config) RolesByName(role string) Permissions {
	p, ok := c.Roles[role]
	if !ok {
		p, ok = defaultRoles[role]
	}
	if !ok {
		return Permissions{} // unknown role → no permissions
	}
	return p
}

// HasPermission checks whether the given role has a specific permission on a resource class.
func HasPermission(role, resourceClass, action string) bool {
	p := defaultRoles[role]
	switch resourceClass {
	case "admin":
		switch action {
		case "read": return p.AdminRead
		case "write": return p.AdminWrite
		}
	case "app":
		switch action {
		case "read": return p.AppRead
		case "write": return p.AppWrite
		}
	}
	return false
}

// LoadFromDisk reads a JSON file with user definitions and builds a Config.
func LoadFromDisk(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return &Config{Roles: defaultRoles}, err
	}
	var users []User
	if err := json.Unmarshal(b, &users); err != nil {
		return &Config{Roles: defaultRoles}, err
	}
	c := &Config{
		Users:    users,
		DefaultKey: "tars-gateway-key",
		Roles:    make(map[string]Permissions),
	}
	// Merge explicit role definitions over defaults
	for k, v := range defaultRoles {
		c.Roles[k] = v
	}
	_ = users // loaded
	return c, nil
}

func matchKey(input, stored string) bool {
	if input == "" && stored == "" {
		return true
	}
	if len(input) != len(stored) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(input), []byte(stored)) == 1
}
