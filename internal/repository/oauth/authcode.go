package oauth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

func (s *Storage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}

	return s.queries.CreateAuthorizationCode(ctx, oidc.CreateAuthorizationCodeParams{
		Code:                code,
		ClientID:            request.GetClient().GetID(),
		UserID:              sess.GetSubject(),
		RedirectUri:         request.GetRequestForm().Get("redirect_uri"),
		Scopes:              strings.Join(request.GetRequestedScopes(), " "),
		CodeChallenge:       sql.NullString{Valid: false},
		CodeChallengeMethod: sql.NullString{Valid: false},
		Nonce: sql.NullString{
			String: request.GetRequestForm().Get("nonce"),
			Valid:  request.GetRequestForm().Get("nonce") != "",
		},
		ExpiresAt: sess.GetExpiresAt(fosite.AuthorizeCode),
	})
}

func (s *Storage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	dbCode, err := s.queries.GetAuthorizationCode(ctx, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if time.Now().After(dbCode.ExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	client, err := s.GetClient(ctx, dbCode.ClientID)
	if err != nil {
		return nil, err
	}

	scopes := strings.Split(dbCode.Scopes, " ")
	if dbCode.Scopes == "" {
		scopes = []string{}
	}

	sess := NewSession(dbCode.UserID)
	sess.SetExpiresAt(fosite.AuthorizeCode, dbCode.ExpiresAt)

	form := make(map[string][]string)
	form["redirect_uri"] = []string{dbCode.RedirectUri}
	if dbCode.CodeChallenge.Valid {
		form["code_challenge"] = []string{dbCode.CodeChallenge.String}
	}
	if dbCode.CodeChallengeMethod.Valid {
		form["code_challenge_method"] = []string{dbCode.CodeChallengeMethod.String}
	}
	if dbCode.Nonce.Valid {
		form["nonce"] = []string{dbCode.Nonce.String}
	}

	req := &fosite.Request{
		ID:          code,
		RequestedAt: dbCode.CreatedAt,
		Client:      client,
		Form:        form,
		Session:     sess,
	}
	req.SetRequestedScopes(scopes)
	for _, scope := range scopes {
		req.GrantScope(scope)
	}
	return req, nil
}

func (s *Storage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.queries.DeleteAuthorizationCode(ctx, code)
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

	return s.queries.UpdateAuthorizationCodePKCE(ctx, oidc.UpdateAuthorizationCodePKCEParams{
		CodeChallenge: sql.NullString{
			String: challenge,
			Valid:  true,
		},
		CodeChallengeMethod: sql.NullString{
			String: method,
			Valid:  method != "",
		},
		Code: signature,
	})
}

func (s *Storage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return nil
}
