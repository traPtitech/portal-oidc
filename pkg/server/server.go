package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/rs/cors"

	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
	repov1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1"
	oauth2infra "github.com/traPtitech/portal-oidc/pkg/infrastructure/oauth2"
	portalv1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1"
	v1 "github.com/traPtitech/portal-oidc/pkg/interface/handler/v1"
	"github.com/traPtitech/portal-oidc/pkg/usecase"
)

func NewServer(config Config) http.Handler {
	repo := initRepository(config)
	po := initPortal(config)
	oauth2Provider := initOAuth2Provider(config, repo)

	uc := usecase.NewUseCase(repo, po)
	handler := v1.NewHandler(uc, oauth2Provider, v1.HandlerConfig{
		Issuer:          config.Host,
		SessionLifespan: DefaultSessionLifespan,
	})

	e := echo.New()

	// OAuth2 endpoints
	e.GET("/oauth2/authorize", handler.AuthEndpoint)
	e.POST("/oauth2/token", handler.TokenEndpoint)
	e.POST("/login", handler.LoginHandler)

	// Client management endpoints
	e.POST("/v1/clients", handler.CreateClientHandler)
	e.GET("/v1/clients", handler.ListClientsHandler)
	e.PUT("/v1/clients/:clientId", handler.UpdateClientHandler)
	e.PUT("/v1/clients/:clientId/secret", handler.UpdateClientSecretHandler)
	e.DELETE("/v1/clients/:clientId", handler.DeleteClientHandler)

	return cors.New(cors.Options{
		AllowOriginFunc:  func(origin string) bool { return true },
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Set-Cookie", "Cookie"},
		AllowCredentials: true,
	}).Handler(e)
}

func initRepository(config Config) repository.Repository {
	if config.Repository != nil {
		return config.Repository
	}
	repo, err := repov1.NewRepository(config.DB)
	if err != nil {
		panic(err)
	}
	return repo
}

func initPortal(config Config) portal.Portal {
	if config.PortalImpl != nil {
		return config.PortalImpl
	}
	po, err := portalv1.NewPortal(config.Portal.DB)
	if err != nil {
		panic(err)
	}
	return po
}

func initOAuth2Provider(config Config, repo repository.Repository) fosite.OAuth2Provider {
	if config.OAuth2Provider != nil {
		return config.OAuth2Provider
	}
	secret := []byte(config.OAuthSecret)
	if len(secret) == 0 {
		secret = []byte("default-secret-for-development-only")
	}
	provider, _ := oauth2infra.NewProvider(repo, oauth2infra.Config{
		Issuer:              config.Host,
		Secret:              secret,
		AuthCodeLifespan:    DefaultAuthCodeLifespan,
		AccessTokenLifespan: DefaultAccessTokenLifespan,
	})
	return provider
}
