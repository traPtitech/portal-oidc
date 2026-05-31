package v1

import (
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"

	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

type Handler struct {
	clientUseCase usecase.ClientUseCase
	oauthUseCase  usecase.OAuthUseCase
	oauth2        fosite.OAuth2Provider
	tokenStrategy *oauth2.HMACSHAStrategy
	userUseCase   usecase.UserUseCase
	tokens        repository.TokenRepository
	deviceAuths   repository.DeviceAuthorizationRepository
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
	oauthUseCase usecase.OAuthUseCase,
	oauth2Provider fosite.OAuth2Provider,
	tokenStrategy *oauth2.HMACSHAStrategy,
	userUseCase usecase.UserUseCase,
	tokens repository.TokenRepository,
	deviceAuths repository.DeviceAuthorizationRepository,
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
		oauthUseCase:  oauthUseCase,
		oauth2:        oauth2Provider,
		tokenStrategy: tokenStrategy,
		userUseCase:   userUseCase,
		tokens:        tokens,
		deviceAuths:   deviceAuths,
		sessions:      store,
		config:        config,
	}
}
