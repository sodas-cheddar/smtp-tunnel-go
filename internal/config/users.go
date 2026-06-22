package config

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// UserConfig is a single user's settings: secret, optional IP whitelist,
// optional per-user logging toggle.
type UserConfig struct {
	Username  string
	Secret    string
	Whitelist []string
	Logging   bool
}

// rawUser mirrors the YAML shape so we can preserve comments and ordering
// when re-saving.
type rawUsersFile struct {
	Users map[string]rawUser `yaml:"users"`
}

type rawUser struct {
	Secret    string   `yaml:"secret"`
	Whitelist []string `yaml:"whitelist,omitempty"`
	Logging   *bool    `yaml:"logging,omitempty"`
}

// LoadUsers reads users.yaml. Returns an empty map if the file does not
// exist (so a fresh install with no users starts cleanly).
func LoadUsers(path string) (map[string]*UserConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]*UserConfig{}, nil
		}
		return nil, err
	}
	var raw rawUsersFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make(map[string]*UserConfig, len(raw.Users))
	for name, r := range raw.Users {
		// Support the legacy simple format `username: "secret-string"`.
		// yaml.v3 will unmarshal a bare string into the struct with all
		// fields zero — but `Secret` will be empty. So we re-check the
		// raw node for the simple form.
		logging := true
		if r.Logging != nil {
			logging = *r.Logging
		}
		out[name] = &UserConfig{
			Username:  name,
			Secret:    r.Secret,
			Whitelist: r.Whitelist,
			Logging:   logging,
		}
	}

	// Second pass: handle the legacy `username: "secret-string"` form by
	// re-decoding into a map[string]any and overwriting where the value
	// is a plain string.
	var anyDoc map[string]any
	if err := yaml.Unmarshal(data, &anyDoc); err == nil {
		if usersMap, ok := anyDoc["users"].(map[string]any); ok {
			for name, v := range usersMap {
				if s, ok := v.(string); ok {
					out[name] = &UserConfig{
						Username: name,
						Secret:   s,
						Logging:  true,
					}
				}
			}
		}
	}

	return out, nil
}

// SaveUsers writes users.yaml in a stable, human-friendly format. The
// output preserves the same shape the Python tools emit, so existing
// admin scripts and docs remain accurate.
func SaveUsers(path string, users map[string]*UserConfig) error {
	var b strings.Builder
	b.WriteString("# SMTP Tunnel Users\n")
	b.WriteString("# Managed by smtp-tunnel-adduser\n\n")
	b.WriteString("users:\n")

	// Stable order: alphabetical.
	names := make([]string, 0, len(users))
	for n := range users {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		u := users[name]
		b.WriteString("  " + name + ":\n")
		b.WriteString("    secret: " + yamlQuote(u.Secret) + "\n")
		// logging always emitted so the field round-trips cleanly.
		b.WriteString("    logging: " + boolStr(u.Logging) + "\n")
		if len(u.Whitelist) > 0 {
			b.WriteString("    whitelist:\n")
			for _, ip := range u.Whitelist {
				b.WriteString("      - " + yamlQuote(ip) + "\n")
			}
		} else {
			b.WriteString("    # whitelist:\n")
			b.WriteString("    #   - 192.168.1.100\n")
			b.WriteString("    #   - 10.0.0.0/8\n")
		}
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// yamlQuote returns a YAML-safe double-quoted string. We always quote to
// avoid any ambiguity with special characters in secrets.
func yamlQuote(s string) string {
	// Replace backslash and quote first, then wrap in double quotes.
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
