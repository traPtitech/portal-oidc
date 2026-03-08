package oauth

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

func (s *Storage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}

	return s.getAuthCodes(ctx).Create(ctx, domain.AuthCode{
		Code:        code,
		ClientID:    request.GetClient().GetID(),
		UserID:      sess.GetSubject(),
		RedirectURI: request.GetRequestForm().Get("redirect_uri"),
		Scopes:      request.GetRequestedScopes(),
		Nonce:       request.GetRequestForm().Get("nonce"),
		ExpiresAt:   sess.GetExpiresAt(fosite.AuthorizeCode),
	})
}

func (s *Storage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	authCode, err := s.getAuthCodes(ctx).Get(ctx, code)
	if err != nil {
		if errors.Is(err, repository.ErrAuthCodeNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	client, err := s.GetClient(ctx, authCode.ClientID)
	if err != nil {
		return nil, err
	}

	sess := NewSession(authCode.UserID, time.Time{})
	sess.SetExpiresAt(fosite.AuthorizeCode, authCode.ExpiresAt)

	form := url.Values{}
	form.Set("redirect_uri", authCode.RedirectURI)
	if authCode.CodeChallenge != "" {
		form.Set("code_challenge", authCode.CodeChallenge)
	}
	if authCode.CodeChallengeMethod != "" {
		form.Set("code_challenge_method", authCode.CodeChallengeMethod)
	}
	if authCode.Nonce != "" {
		form.Set("nonce", authCode.Nonce)
	}

	req := newFositeRequest(code, authCode.CreatedAt, client, sess, authCode.Scopes, form)

	if authCode.Used {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	return req, nil
}

func (s *Storage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.getAuthCodes(ctx).MarkUsed(ctx, code)
}

func (s *Storage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.GetAuthorizeCodeSession(ctx, signature, session)
}

func (s *Storage) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	challenge := requester.GetRequestForm().Get("code_challenge")
	method := requester.GetRequestForm().Get("code_challenge_method")

	if challenge == "" {
		return nil
	}

	return s.getAuthCodes(ctx).UpdatePKCE(ctx, signature, challenge, method)
}

func (s *Storage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return nil
}
