package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"

	"github.com/traPtitech/portal-oidc/internal/repository"
)

type OAuthProviderConfig struct {
	Issuer               string
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
	AuthCodeLifespan     time.Duration
	IDTokenLifespan      time.Duration
	Secret               []byte
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

func newOAuthProvider(storage *repository.OAuthStorage, config OAuthProviderConfig, privateKey *rsa.PrivateKey) fosite.OAuth2Provider {
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
		EnforcePKCEForPublicClients:    false,
		EnablePKCEPlainChallengeMethod: false,
		AccessTokenIssuer:              config.Issuer,
		IDTokenIssuer:                  config.Issuer,
	}

	privateKeyGetter := func(_ context.Context) (interface{}, error) {
		return privateKey, nil
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

func loadOrGenerateKey(path string) (*rsa.PrivateKey, error) {
	key, err := loadKey(path)
	if err == nil {
		return key, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	if err := saveKey(path, key); err != nil {
		return nil, err
	}

	return key, nil
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from config
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func saveKey(path string, key *rsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return os.WriteFile(path, data, 0o600)
}
