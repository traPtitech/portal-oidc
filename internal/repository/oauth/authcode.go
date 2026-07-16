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
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	return req, nil
}

func (s *Storage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.getAuthCodes(ctx).MarkUsed(ctx, code)
}

func (s *Storage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	req, err := s.GetAuthorizeCodeSession(ctx, signature, session)
	if err != nil {
		return nil, err
	}
	if req.GetRequestForm().Get("code_challenge") == "" {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *Storage) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	challenge := requester.GetRequestForm().Get("code_challenge")
	method := requester.GetRequestForm().Get("code_challenge_method")

	if challenge == "" {
		return nil
	}

	return s.getAuthCodes(ctx).UpdatePKCE(ctx, signature, challenge, method)
}

// Defer PKCE cleanup to authorization-code invalidation because Fosite calls this before verifier validation.
func (s *Storage) DeletePKCERequestSession(_ context.Context, _ string) error {
	return nil
}
