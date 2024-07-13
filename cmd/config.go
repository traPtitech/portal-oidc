package main

import (
	"github.com/spf13/viper"
)

func setupDefaults() {
	viper.SetDefault("oidc_secret", "some-cool-secret-that-is-32bytes")
}
