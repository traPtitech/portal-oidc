package server

import (
	repov1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1"
	portalv1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1"
)

type Config struct {
	Host       string `mapstructure:"host"`
	OIDCSecret string `mapstructure:"oidc_secret"`
	Portal     struct {
		DB portalv1.Config `mapstructure:"db"`
	} `mapstructure:"portal"`
	DB repov1.Config `mapstructure:"db"`
}
