package oauth

import (
	"context"
	"errors"
	"net/url"

	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

func (s *Storage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	sess, ok := requester.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}

	return s.getOIDCSessions(ctx).Create(ctx, domain.OIDCSession{
		AuthorizeCode: authorizeCode,
		ClientID:      requester.GetClient().GetID(),
		UserID:        sess.GetSubject(),
		Nonce:         requester.GetRequestForm().Get("nonce"),
		AuthTime:      sess.IDTokenClaims().AuthTime,
		Scopes:        requester.GetGrantedScopes(),
		RequestedAt:   requester.GetRequestedAt(),
	})
}

func (s *Storage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, _ fosite.Requester) (fosite.Requester, error) {
	oidcSession, err := s.getOIDCSessions(ctx).Get(ctx, authorizeCode)
	if err != nil {
		if errors.Is(err, repository.ErrOIDCSessionNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, oidcSession.ClientID)
	if err != nil {
		return nil, err
	}

	sess := NewSession(oidcSession.UserID, oidcSession.AuthTime)

	form := url.Values{}
	if oidcSession.Nonce != "" {
		form.Set("nonce", oidcSession.Nonce)
	}

	return newFositeRequest(authorizeCode, oidcSession.RequestedAt, client, sess, oidcSession.Scopes, form), nil
}

func (s *Storage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return s.getOIDCSessions(ctx).Delete(ctx, authorizeCode)
}
