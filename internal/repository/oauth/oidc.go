package oauth

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

// authorizeCodeSignature extracts the signature portion of a fosite-issued
// authorization code. fosite emits codes formatted as "<key>.<signature>"
// (HMACStrategy) and stores the signature alone as the lookup key in
// CreateAuthorizeCodeSession. CreateOpenIDConnectSession, however, is invoked
// with the full code, so we strip the key half here to keep oidc_sessions
// referentially consistent with authorization_codes.
func authorizeCodeSignature(code string) string {
	if idx := strings.LastIndex(code, "."); idx >= 0 && idx+1 < len(code) {
		return code[idx+1:]
	}
	return code
}

func (s *Storage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	sess, ok := requester.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}

	clientID, err := uuid.Parse(requester.GetClient().GetID())
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(sess.GetSubject())
	if err != nil {
		return err
	}

	return s.getOIDCSessions(ctx).Create(ctx, domain.OIDCSession{
		AuthorizeCode: authorizeCodeSignature(authorizeCode),
		ClientID:      clientID,
		UserID:        userID,
		Nonce:         requester.GetRequestForm().Get("nonce"),
		AuthTime:      sess.IDTokenClaims().AuthTime,
		Scopes:        requester.GetGrantedScopes(),
		RequestedAt:   requester.GetRequestedAt(),
	})
}

func (s *Storage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, _ fosite.Requester) (fosite.Requester, error) {
	oidcSession, err := s.getOIDCSessions(ctx).Get(ctx, authorizeCodeSignature(authorizeCode))
	if err != nil {
		if errors.Is(err, repository.ErrOIDCSessionNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, oidcSession.ClientID.String())
	if err != nil {
		return nil, err
	}

	sess := NewSession(oidcSession.UserID.String(), oidcSession.AuthTime)

	form := url.Values{}
	if oidcSession.Nonce != "" {
		form.Set("nonce", oidcSession.Nonce)
	}

	return newFositeRequest(authorizeCode, oidcSession.RequestedAt, client, sess, oidcSession.Scopes, form), nil
}

func (s *Storage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return s.getOIDCSessions(ctx).Delete(ctx, authorizeCodeSignature(authorizeCode))
}
