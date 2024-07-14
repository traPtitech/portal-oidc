package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"

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

	handler := v1.NewHandler(usecase, store, signer, []byte(config.OIDCSecret))

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/auth", handler.AuthEndpoint)
	mux.HandleFunc("/oauth2/token", handler.TokenEndpoint)
	mux.HandleFunc("/oauth2/userinfo", handler.UserInfoEndpoint)
	mux.HandleFunc("/.well-known/openid-configuration", handler.SetupOIDCDiscoveryHandler(config.Host))

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
	}).Handler(mux)
}
