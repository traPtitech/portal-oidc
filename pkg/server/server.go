package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"

	"github.com/rs/cors"

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

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/auth", handler.AuthEndpoint)
	mux.HandleFunc("/oauth2/token", handler.TokenEndpoint)

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
