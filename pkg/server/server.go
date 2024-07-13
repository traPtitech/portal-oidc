package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"

	"github.com/rs/cors"

	"github.com/labstack/echo/v4"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"

	v1 "github.com/traPtitech/portal-oidc/pkg/interface/handler/v1"
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

	handler := v1.NewHandler(store, signer, []byte(config.OIDCSecret))

	e := echo.New()
	oauth2Route := e.Group("/oauth2")
	oauth2Route.Any("/auth", handler.AuthEndpoint)
	oauth2Route.Any("/token", handler.TokenEndpoint)

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
