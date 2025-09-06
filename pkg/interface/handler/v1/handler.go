package v1

import (
	"time"

	"github.com/traPtitech/portal-oidc/pkg/domain/store"
	es256jwt "github.com/traPtitech/portal-oidc/pkg/infrastructure/jwt"
	"github.com/traPtitech/portal-oidc/pkg/usecase"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
)

type Config struct {
	Issuer          string
	SessionLifespan time.Duration
}

type Handler struct {
	oauth2  fosite.OAuth2Provider
	usecase usecase.UseCase
	conf    Config
}

func NewHandler(u usecase.UseCase, st store.Store, signer *es256jwt.RotatingSigner, globalSecret []byte, conf Config) *Handler {
	fconf := &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		GlobalSecret:        globalSecret,
	}

	es256Strategy := es256jwt.NewES256JWTStrategy(signer, fconf)

	provider := compose.Compose(
		fconf,
		st,
		&compose.CommonStrategy{
			CoreStrategy: es256Strategy,
			OpenIDConnectTokenStrategy: &openid.DefaultStrategy{
				Signer: signer,
				Config: fconf,
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
		oauth2:  provider,
		usecase: u,
		conf:    conf,
	}
}