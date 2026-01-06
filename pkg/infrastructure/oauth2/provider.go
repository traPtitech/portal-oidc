package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"

	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
)

type Config struct {
	Issuer              string
	Secret              []byte
	AuthCodeLifespan    time.Duration
	AccessTokenLifespan time.Duration
}

type privateKeyProvider struct {
	key *rsa.PrivateKey
}

func (p *privateKeyProvider) GetPrivateKey(ctx context.Context) (interface{}, error) {
	return p.key, nil
}

func NewProvider(repo repository.Repository, config Config) (fosite.OAuth2Provider, *Store) {
	store := NewStore(repo)

	// Generate RSA key for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        config.AccessTokenLifespan,
		AuthorizeCodeLifespan:      config.AuthCodeLifespan,
		GlobalSecret:               config.Secret,
		TokenURL:                   config.Issuer + "/oauth2/token",
		SendDebugMessagesToClients: true,
	}

	keyProvider := &privateKeyProvider{key: privateKey}

	// Only compose Authorization Code flow (minimal)
	provider := compose.Compose(
		fositeConfig,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(fositeConfig),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyProvider.GetPrivateKey, fositeConfig),
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
	)

	return provider, store
}
