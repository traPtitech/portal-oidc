package v1

import (
	"time"

	"github.com/traPtitech/portal-oidc/pkg/domain/store"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

type Handler struct {
	oauth2 fosite.OAuth2Provider
}

func NewHandler(st store.Store, signer jwt.Signer, globalSecret []byte) *Handler {
	conf := &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		GlobalSecret:        globalSecret,
	}

	provider := compose.Compose(
		conf,
		st,
		&compose.CommonStrategy{
			CoreStrategy: &oauth2.DefaultJWTStrategy{
				Signer:          signer,
				HMACSHAStrategy: compose.NewOAuth2HMACStrategy(conf),
				Config:          conf,
			},
			OpenIDConnectTokenStrategy: &openid.DefaultStrategy{
				Signer: signer,
				Config: conf,
			},
			Signer: signer,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.RFC7523AssertionGrantFactory,

		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectHybridFactory,
		compose.OpenIDConnectRefreshFactory,

		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,

		compose.OAuth2PKCEFactory,
	)
	return &Handler{
		oauth2: provider,
	}
}
