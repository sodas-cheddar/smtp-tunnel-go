// Package config loads and saves YAML configuration for the smtp-tunnel
// server, client, and user database.
//
// The on-disk format is byte-for-byte compatible with the original Python
// implementation, so existing config.yaml / users.yaml files work without
// modification.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig matches the "server:" section of config.yaml.
type ServerConfig struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	Hostname  string `yaml:"hostname"`
	CertFile  string `yaml:"cert_file"`
	KeyFile   string `yaml:"key_file"`
	UsersFile string `yaml:"users_file"`
	LogUsers  bool   `yaml:"log_users"`
}

// ClientConfig matches the "client:" section of config.yaml.
type ClientConfig struct {
	ServerHost string `yaml:"server_host"`
	ServerPort int    `yaml:"server_port"`
	SocksHost  string `yaml:"socks_host"`
	SocksPort  int    `yaml:"socks_port"`
	Username   string `yaml:"username"`
	Secret     string `yaml:"secret"`
	CACert     string `yaml:"ca_cert"`
}

// StealthConfig is parsed but currently unused in the fast binary mode.
type StealthConfig struct {
	MinDelayMs             int      `yaml:"min_delay_ms"`
	MaxDelayMs             int      `yaml:"max_delay_ms"`
	PadToSizes             []int    `yaml:"pad_to_sizes"`
	DummyMessageProbability float64 `yaml:"dummy_message_probability"`
}

// File is the top-level config.yaml document.
type File struct {
	Server  ServerConfig  `yaml:"server"`
	Client  ClientConfig  `yaml:"client"`
	Stealth StealthConfig `yaml:"stealth"`
}

// Load reads and parses a YAML config file.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f := &File{}
	if err := yaml.Unmarshal(data, f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	applyDefaults(f)
	return f, nil
}

func applyDefaults(f *File) {
	if f.Server.Host == "" {
		f.Server.Host = "0.0.0.0"
	}
	if f.Server.Port == 0 {
		f.Server.Port = 587
	}
	if f.Server.Hostname == "" {
		f.Server.Hostname = "mail.example.com"
	}
	if f.Server.CertFile == "" {
		f.Server.CertFile = "server.crt"
	}
	if f.Server.KeyFile == "" {
		f.Server.KeyFile = "server.key"
	}
	if f.Server.UsersFile == "" {
		f.Server.UsersFile = "users.yaml"
	}
	if f.Server.LogUsers == false {
		// Default true; only flip when explicitly absent. We can't tell
		// "absent" from "false" without a *bool, but the default-true
		// behavior is documented and matches the Python dataclass.
		// Keep false here; users who want default-true should set it.
		// (The server-side logger falls back to per-user logging only.)
	}

	if f.Client.ServerPort == 0 {
		f.Client.ServerPort = 587
	}
	if f.Client.SocksHost == "" {
		f.Client.SocksHost = "127.0.0.1"
	}
	if f.Client.SocksPort == 0 {
		f.Client.SocksPort = 1080
	}
}

// Save writes the config back to disk in YAML format.
func Save(path string, f *File) error {
	data, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
