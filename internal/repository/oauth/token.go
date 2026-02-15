package oauth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

func (s *Storage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}

	tokenID := uuid.New()
	return s.queries.CreateToken(ctx, oidc.CreateTokenParams{
		ID:          tokenID.String(),
		ClientID:    request.GetClient().GetID(),
		UserID:      sess.GetSubject(),
		AccessToken: signature,
		RefreshToken: sql.NullString{
			Valid: false,
		},
		Scopes:    strings.Join(request.GetGrantedScopes(), " "),
		ExpiresAt: sess.GetExpiresAt(fosite.AccessToken),
	})
}

func (s *Storage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	dbToken, err := s.queries.GetTokenByAccessToken(ctx, signature)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if time.Now().After(dbToken.ExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	client, err := s.GetClient(ctx, dbToken.ClientID)
	if err != nil {
		return nil, err
	}

	scopes := strings.Split(dbToken.Scopes, " ")
	if dbToken.Scopes == "" {
		scopes = []string{}
	}

	sess := NewSession(dbToken.UserID)
	sess.SetExpiresAt(fosite.AccessToken, dbToken.ExpiresAt)

	req := &fosite.Request{
		ID:          dbToken.ID,
		RequestedAt: dbToken.CreatedAt,
		Client:      client,
		Session:     sess,
	}
	req.SetRequestedScopes(scopes)
	for _, scope := range scopes {
		req.GrantScope(scope)
	}
	return req, nil
}

func (s *Storage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.queries.DeleteTokenByAccessToken(ctx, signature)
}

func (s *Storage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}

	tokenID := uuid.New()
	return s.queries.CreateToken(ctx, oidc.CreateTokenParams{
		ID:          tokenID.String(),
		ClientID:    request.GetClient().GetID(),
		UserID:      sess.GetSubject(),
		AccessToken: accessSignature,
		RefreshToken: sql.NullString{
			String: signature,
			Valid:  true,
		},
		Scopes:    strings.Join(request.GetGrantedScopes(), " "),
		ExpiresAt: sess.GetExpiresAt(fosite.RefreshToken),
	})
}

func (s *Storage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return nil
}

func (s *Storage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	dbToken, err := s.queries.GetTokenByRefreshToken(ctx, sql.NullString{String: signature, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, dbToken.ClientID)
	if err != nil {
		return nil, err
	}

	scopes := strings.Split(dbToken.Scopes, " ")
	if dbToken.Scopes == "" {
		scopes = []string{}
	}

	sess := NewSession(dbToken.UserID)
	sess.SetExpiresAt(fosite.RefreshToken, dbToken.ExpiresAt)

	req := &fosite.Request{
		ID:          dbToken.ID,
		RequestedAt: dbToken.CreatedAt,
		Client:      client,
		Session:     sess,
	}
	req.SetRequestedScopes(scopes)
	for _, scope := range scopes {
		req.GrantScope(scope)
	}
	return req, nil
}

func (s *Storage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.queries.DeleteTokenByRefreshToken(ctx, sql.NullString{String: signature, Valid: true})
}

func (s *Storage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return nil
}

func (s *Storage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	return s.DeleteRefreshTokenSession(ctx, signature)
}

func (s *Storage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return nil
}
