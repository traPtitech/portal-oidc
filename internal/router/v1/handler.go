package v1

import (
	"crypto/rsa"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/usecase"
)

type Handler struct {
	clientUseCase usecase.ClientUseCase
	oauth2        fosite.OAuth2Provider
	sessions      *sessions.CookieStore
	config        OAuthConfig
}

type OAuthConfig struct {
	Issuer        string
	SessionSecret []byte
	PrivateKey    *rsa.PrivateKey
	Environment   string
	TestUserID    string
}

func NewHandler(
	clientUseCase usecase.ClientUseCase,
	oauth2 fosite.OAuth2Provider,
	config OAuthConfig,
) *Handler {
	store := sessions.NewCookieStore(config.SessionSecret)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	return &Handler{
		clientUseCase: clientUseCase,
		oauth2:        oauth2,
		sessions:      store,
		config:        config,
	}
}
