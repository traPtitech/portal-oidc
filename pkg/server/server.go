package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/cors"

	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"

	repov1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1"
	portalv1 "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1"
	v1 "github.com/traPtitech/portal-oidc/pkg/interface/handler/v1"
	"github.com/traPtitech/portal-oidc/pkg/usecase"
)

func NewServer(config Config) http.Handler {

	store := storage.NewMemoryStore()
	// TODO: 設定ファイルから読み込むようにする
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	signer := &jwt.DefaultSigner{
		GetPrivateKey: func(_ context.Context) (interface{}, error) {
			return privateKey, nil
		},
	}

	po, err := portalv1.NewPortal(config.Portal.DB)
	if err != nil {
		panic(err)
	}

	repo, err := repov1.NewRepository(config.DB)
	if err != nil {
		panic(err)
	}

	usecase := usecase.NewUseCase(repo, po, po)

	handler := v1.NewHandler(usecase, store, signer, []byte(config.OIDCSecret), v1.Config{
		Issuer:          config.Host,
		SessionLifespan: config.SessionLifespan,
	})

	e := echo.New()
	e.Any("/oauth2/auth", handler.AuthEndpoint)
	e.Any("/oauth2/token", handler.TokenEndpoint)
	e.Any("/oauth2/userinfo", handler.UserInfoEndpoint)
	e.Any("/oauth2/revoke", handler.RevokeEndpoint)
	e.Any("/oauth2/introspect", handler.IntrospectionEndpoint)
	e.Any("/.well-known/openid-configuration", handler.SetupOIDCDiscoveryHandler(config.Host))

	e.POST("/v1/clients", handler.CreateClientHandler)
	e.GET("/v1/clients", handler.ListClientsHandler)
	e.PUT("/v1/clients", handler.UpdateClientHandler)
	e.PUT("/v1/clients/secret", handler.UpdateClientSecretHandler)
	e.DELETE("/v1/clients", handler.DeleteClientHandler)

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
