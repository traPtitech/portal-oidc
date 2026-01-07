package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/cors"

	repov1 "github.com/traPtitech/portal-oidc/internal/infrastructure/postgres"
	portalv1 "github.com/traPtitech/portal-oidc/internal/infrastructure/portal"
	v1 "github.com/traPtitech/portal-oidc/internal/interface/handler/v1"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

func NewServer(config Config) http.Handler {
	// Use injected dependencies if provided, otherwise create from config
	repo := config.Repository
	if repo == nil {
		var err error
		repo, err = repov1.NewRepository(config.DB)
		if err != nil {
			panic(err)
		}
	}

	po := config.PortalImpl
	if po == nil {
		var err error
		po, err = portalv1.NewPortal(config.Portal.DB)
		if err != nil {
			panic(err)
		}
	}

	uc := usecase.NewUseCase(repo, po)
	handler := v1.NewHandler(uc)

	e := echo.New()

	// Client management endpoints
	e.POST("/v1/clients", handler.CreateClientHandler)
	e.GET("/v1/clients", handler.ListClientsHandler)
	e.PUT("/v1/clients/:clientId", handler.UpdateClientHandler)
	e.PUT("/v1/clients/:clientId/secret", handler.UpdateClientSecretHandler)
	e.DELETE("/v1/clients/:clientId", handler.DeleteClientHandler)

	return cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Set-Cookie", "Cookie"},
		AllowCredentials: true,
	}).Handler(e)
}
