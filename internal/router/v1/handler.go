package v1

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/keymanager"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

// KeyProvider abstracts the JWT signing key store so the router does not
// depend on its concrete implementation. Tests can supply an in-memory fake
// without dragging in the keymanager package.
type KeyProvider interface {
	ActiveKey() (*rsa.PrivateKey, string, error)
	PublishableKeys(ctx context.Context) ([]keymanager.PublicKeyView, error)
}

type Handler struct {
	clientUseCase usecase.ClientUseCase
	oauthUseCase  usecase.OAuthUseCase
	oauth2        fosite.OAuth2Provider
	userUseCase   usecase.UserUseCase
	sessions      *sessions.CookieStore
	keys          KeyProvider
	config        OAuthConfig
}

type OAuthConfig struct {
	Issuer        string
	SessionSecret []byte // #nosec G117 -- internal config, not serialized
	Environment   string
	TestUserID    string
}

func NewHandler(
	clientUseCase usecase.ClientUseCase,
	oauthUseCase usecase.OAuthUseCase,
	oauth2 fosite.OAuth2Provider,
	userUseCase usecase.UserUseCase,
	keys KeyProvider,
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
		oauth2:        oauth2,
		userUseCase:   userUseCase,
		sessions:      store,
		keys:          keys,
		config:        config,
	}
}
