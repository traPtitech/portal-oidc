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
	Host        string         `koanf:"host"`
	Environment string         `koanf:"environment"`
	Database    DatabaseConfig `koanf:"database"`
	Portal      PortalConfig   `koanf:"portal"`
	OAuth       OAuthConfig    `koanf:"oauth"`
}

type PortalConfig struct {
	Database DatabaseConfig `koanf:"database"`
}

type DatabaseConfig struct {
	Host     string `koanf:"host"`
	Port     int    `koanf:"port"`
	User     string `koanf:"user"`
	Password string `koanf:"password"`
	Name     string `koanf:"name"`
}

type OAuthConfig struct {
	Secret     string `koanf:"secret"`
	KeyFile    string `koanf:"key_file"`
	TestUserID string `koanf:"test_user_id"`
}

var defaults = map[string]any{
	"host":                     "http://localhost:8080",
	"environment":              "development",
	"database.host":            "localhost",
	"database.port":            3307,
	"database.user":            "root",
	"database.password":        "password",
	"database.name":            "oidc",
	"portal.database.host":     "localhost",
	"portal.database.port":     3306,
	"portal.database.user":     "root",
	"portal.database.password": "password",
	"portal.database.name":     "portal",
	"oauth.secret":             "my-super-secret-signing-key-32!!",
	"oauth.key_file":           "data/private.pem",
	"oauth.test_user_id":       "testuser",
}

func loadConfig(configPath string) (*Config, error) {
	k := koanf.New(".")

	if err := k.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return nil, err
	}

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

	if err := k.Load(env.Provider("OIDC_", ".", func(s string) string {
		key := strings.ToLower(strings.TrimPrefix(s, "OIDC_"))
		return strings.ReplaceAll(key, "_", ".")
	}), nil); err != nil {
		return nil, err
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
