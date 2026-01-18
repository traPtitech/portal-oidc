package main

import (
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	Host     string         `koanf:"host"`
	Database DatabaseConfig `koanf:"database"`
	OAuth    OAuthConfig    `koanf:"oauth"`
}

type DatabaseConfig struct {
	Host     string `koanf:"host"`
	Port     int    `koanf:"port"`
	User     string `koanf:"user"`
	Password string `koanf:"password"`
	Name     string `koanf:"name"`
}

type OAuthConfig struct {
	Secret  string `koanf:"secret"`
	KeyFile string `koanf:"key_file"`
}

var defaults = map[string]any{
	"host":              "http://localhost:8080",
	"database.host":     "localhost",
	"database.port":     3307,
	"database.user":     "root",
	"database.password": "password",
	"database.name":     "oidc",
	"oauth.secret":      "my-super-secret-signing-key-32!!", // 32 bytes
	"oauth.key_file":    "data/private.pem",
}

func loadConfig(configPath string) (*Config, error) {
	k := koanf.New(".")

	// 1. Load defaults
	if err := k.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return nil, err
	}

	// 2. Load config file
	path := configPath
	if path == "" {
		path = "config.yaml"
	}

	if _, err := os.Stat(path); err == nil {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, err
		}
	} else if configPath != "" {
		return nil, err
	}

	// 3. Load environment variables (OIDC_HOST -> host)
	if err := k.Load(env.Provider("OIDC_", ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, "OIDC_"))
	}), nil); err != nil {
		return nil, err
	}

	// 4. Unmarshal to struct
	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
