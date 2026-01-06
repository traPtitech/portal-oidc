package server

import (
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
	repov1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1"
	portalv1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1"
)

type Config struct {
	Host   string `mapstructure:"host"`
	Portal struct {
		DB portalv1.Config `mapstructure:"db"`
	} `mapstructure:"portal"`
	DB repov1.Config `mapstructure:"db"`

	// For testing: if set, use these instead of creating from config
	Repository repository.Repository `mapstructure:"-"`
	PortalImpl portal.Portal         `mapstructure:"-"`
}
