package v1

import (
	"time"

	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/pkg/usecase"
)

type HandlerConfig struct {
	Issuer          string
	SessionLifespan time.Duration
}

type Handler struct {
	usecase usecase.UseCase
	oauth2  fosite.OAuth2Provider
	conf    HandlerConfig
}

func NewHandler(u usecase.UseCase, oauth2 fosite.OAuth2Provider, conf HandlerConfig) *Handler {
	return &Handler{
		usecase: u,
		oauth2:  oauth2,
		conf:    conf,
	}
}
