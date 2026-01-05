package server

import (
	"time"

	repov1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1"
	portalv1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1"
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
	"github.com/traPtitech/portal-oidc/pkg/domain/store"
)

type Config struct {
	Host            string        `mapstructure:"host"`
	OIDCSecret      string        `mapstructure:"oidc_secret"`
	SessionLifespan time.Duration `mapstructure:"session_lifespan"`
	Portal          struct {
		DB portalv1.Config `mapstructure:"db"`
	} `mapstructure:"portal"`
	DB repov1.Config `mapstructure:"db"`

	// For testing: if set, use these instead of creating from config
	Repository repository.Repository `mapstructure:"-"`
	PortalImpl portal.Portal         `mapstructure:"-"`
	Store      store.Store           `mapstructure:"-"`
}
