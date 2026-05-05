package main

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"

	"github.com/traPtitech/portal-oidc/internal/keymanager"
)

type OAuthProviderConfig struct {
	Issuer               string
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
	AuthCodeLifespan     time.Duration
	IDTokenLifespan      time.Duration
	Secret               []byte // #nosec G117 -- internal config, not serialized
}

func defaultOAuthProviderConfig() OAuthProviderConfig {
	return OAuthProviderConfig{
		Issuer:               "http://localhost:8080",
		AccessTokenLifespan:  time.Hour,
		RefreshTokenLifespan: 30 * 24 * time.Hour,
		AuthCodeLifespan:     5 * time.Minute,
		IDTokenLifespan:      time.Hour,
		Secret:               []byte("my-super-secret-signing-key-32!!"),
	}
}

func newOAuthProvider(storage fosite.Storage, config OAuthProviderConfig, keys *keymanager.Manager) fosite.OAuth2Provider {
	fositeConfig := &fosite.Config{
		AccessTokenLifespan:            config.AccessTokenLifespan,
		RefreshTokenLifespan:           config.RefreshTokenLifespan,
		AuthorizeCodeLifespan:          config.AuthCodeLifespan,
		IDTokenLifespan:                config.IDTokenLifespan,
		GlobalSecret:                   config.Secret,
		ScopeStrategy:                  fosite.ExactScopeStrategy,
		AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
		SendDebugMessagesToClients:     false,
		EnforcePKCE:                    false,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
		AccessTokenIssuer:              config.Issuer,
		IDTokenIssuer:                  config.Issuer,
	}

	// Resolve the active signing key on every request so a manual rotation via
	// the keymanager is picked up without restarting fosite.
	privateKeyGetter := func(_ context.Context) (interface{}, error) {
		key, _, err := keys.ActiveKey()
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	return compose.Compose(
		fositeConfig,
		storage,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(fositeConfig),
			Signer:                     &jwt.DefaultSigner{GetPrivateKey: privateKeyGetter},
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(privateKeyGetter, fositeConfig),
		},

		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
	)
}
