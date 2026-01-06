package server

import (
	"time"

	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
	repov1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1"
	portalv1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1"
)

type Config struct {
	Host        string `mapstructure:"host"`
	OAuthSecret string `mapstructure:"oauth_secret"`
	Portal      struct {
		DB portalv1.Config `mapstructure:"db"`
	} `mapstructure:"portal"`
	DB repov1.Config `mapstructure:"db"`

	// For testing: if set, use these instead of creating from config
	Repository     repository.Repository `mapstructure:"-"`
	PortalImpl     portal.Portal         `mapstructure:"-"`
	OAuth2Provider fosite.OAuth2Provider `mapstructure:"-"`
}

const (
	DefaultSessionLifespan     = 24 * time.Hour
	DefaultAuthCodeLifespan    = 10 * time.Minute
	DefaultAccessTokenLifespan = 1 * time.Hour
)
