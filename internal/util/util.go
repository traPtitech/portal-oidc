package util

import (
	"errors"
	"log"
	"strings"

	"github.com/spf13/viper"
)

func CobraOnInitializeFunc(configFilePath *string, envPrefix string, config interface{}) func() {
	return func() {
		if len(*configFilePath) > 0 {
			viper.SetConfigFile(*configFilePath)
		} else {
			viper.AddConfigPath(".")
			viper.SetConfigName("config")
		}
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		viper.SetEnvPrefix(envPrefix)
		viper.AutomaticEnv()
		if err := viper.ReadInConfig(); err != nil {
			var configFileNotFoundError viper.ConfigFileNotFoundError
			if !errors.As(err, &configFileNotFoundError) {
				log.Fatalf("failed to read config file: %v", err)
			}
		}
		if err := viper.Unmarshal(config); err != nil {
			log.Fatalf("failed to unmarshal config: %v", err)
		}
	}
}
