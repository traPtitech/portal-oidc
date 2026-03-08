package v1

import (
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/usecase"
)

type Handler struct {
	clientUseCase usecase.ClientUseCase
	oauth2        fosite.OAuth2Provider
	userUseCase   usecase.UserUseCase
	sessions      *sessions.CookieStore
	config        OAuthConfig
}

type OAuthConfig struct {
	Issuer        string
	SessionSecret []byte // #nosec G117 -- internal config, not serialized
	PrivateKey    *rsa.PrivateKey
	Environment   string
	TestUserID    string
}

func NewHandler(
	clientUseCase usecase.ClientUseCase,
	oauth2 fosite.OAuth2Provider,
	userUseCase usecase.UserUseCase,
	config OAuthConfig,
) *Handler {
	store := sessions.NewCookieStore(config.SessionSecret)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   strings.HasPrefix(config.Issuer, "https://"),
		SameSite: http.SameSiteLaxMode,
	}

	return &Handler{
		clientUseCase: clientUseCase,
		oauth2:        oauth2,
		userUseCase:   userUseCase,
		sessions:      store,
		config:        config,
	}
}
