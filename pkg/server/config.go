package server

type Config struct {
	OIDCSecret string `mapstructure:"oidc_secret"`
}
