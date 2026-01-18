package main

import (
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/traPtitech/portal-oidc/internal/server"
)

var defaults = map[string]any{
	"host":              "localhost",
	"database.host":     "localhost",
	"database.port":     3307,
	"database.user":     "root",
	"database.password": "password",
	"database.name":     "oidc",
}

func loadConfig(configPath string) (*server.Config, error) {
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
	var cfg server.Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
