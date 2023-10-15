package util

import (
	"log"
	"strings"

	"github.com/ory/viper"
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
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				log.Fatalf("failed to read config file: %v", err)
			}
		}
		if err := viper.Unmarshal(config); err != nil {
			log.Fatalf("failed to unmarshal config: %v", err)
		}
	}
}
