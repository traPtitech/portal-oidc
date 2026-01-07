package main

import (
	"github.com/spf13/viper"
)

func setupDefaults() {
	viper.SetDefault("host", "localhost")
}
