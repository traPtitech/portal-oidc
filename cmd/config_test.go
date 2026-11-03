package main

import "testing"

func TestRepositoryConfigKeepsSessionDefaults(t *testing.T) {
	cfg, err := loadConfig("../config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuth.Secret == "" || cfg.OAuth.KeyFile == "" {
		t.Fatal("repository configuration must preserve the OAuth session/key defaults")
	}
}
