package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/rs/cors"

	"github.com/traPtitech/portal-oidc/pkg/domain/store"
	repov1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1"
	portalv1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1"
	v1 "github.com/traPtitech/portal-oidc/pkg/interface/handler/v1"
	"github.com/traPtitech/portal-oidc/pkg/usecase"
)

func NewServer(config Config) http.Handler {
	// Use injected store if provided, otherwise create new
	var oidcStore store.Store
	if config.Store != nil {
		oidcStore = config.Store
	} else {
		oidcStore = storage.NewMemoryStore()
	}

	// TODO: 設定ファイルから読み込むようにする
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	signer := &jwt.DefaultSigner{
		GetPrivateKey: func(_ context.Context) (any, error) {
			return privateKey, nil
		},
	}

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

	usecase := usecase.NewUseCase(repo, po)

	handler := v1.NewHandler(usecase, oidcStore, signer, []byte(config.OIDCSecret), v1.Config{
		Issuer:          config.Host,
		SessionLifespan: config.SessionLifespan,
	})

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
		AllowedHeaders: []string{"*"},
		ExposedHeaders: []string{
			"Set-Cookie",
			"Cookie",
		},
		AllowCredentials: true,
	}).Handler(e)
}
