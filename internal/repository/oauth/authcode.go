package oauth

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

func (s *Storage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}

	clientID, err := uuid.Parse(request.GetClient().GetID())
	if err != nil {
		return err
	}
	userID, err := uuid.Parse(sess.GetSubject())
	if err != nil {
		return err
	}

	return s.getAuthCodes(ctx).Create(ctx, domain.AuthCode{
		Code:        code,
		ClientID:    clientID,
		UserID:      userID,
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

	client, err := s.GetClient(ctx, authCode.ClientID.String())
	if err != nil {
		return nil, err
	}

	sess := NewSession(authCode.UserID.String(), time.Time{})
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
		// RFC 6749 §4.1.2: on auth code reuse, revoke every token derived from
		// the original exchange. The auth code is the fosite request_id (see
		// newFositeRequest in storage.go), so request_id-keyed deletion covers
		// every issued access and refresh token. Errors are joined with the
		// invalidation error so fosite still detects the reuse via errors.Is.
		var revokeErr error
		if delErr := s.getAccessTokens(ctx).DeleteByRequestID(ctx, code); delErr != nil {
			revokeErr = errors.Join(revokeErr, delErr)
		}
		if delErr := s.getRefreshTokens(ctx).DeleteByRequestID(ctx, code); delErr != nil {
			revokeErr = errors.Join(revokeErr, delErr)
		}
		if revokeErr != nil {
			return req, errors.Join(fosite.ErrInvalidatedAuthorizeCode, revokeErr)
		}
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
