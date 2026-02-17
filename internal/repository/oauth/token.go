package oauth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

func (s *Storage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}

	return s.getTokens(ctx).Create(ctx, domain.Token{
		ID:          uuid.New().String(),
		RequestID:   request.GetID(),
		ClientID:    request.GetClient().GetID(),
		UserID:      sess.GetSubject(),
		AccessToken: signature,
		Scopes:      request.GetGrantedScopes(),
		ExpiresAt:   sess.GetExpiresAt(fosite.AccessToken),
	})
}

func (s *Storage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	token, err := s.getTokens(ctx).GetByAccessToken(ctx, signature)
	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	client, err := s.GetClient(ctx, token.ClientID)
	if err != nil {
		return nil, err
	}

	sess := NewSession(token.UserID, time.Time{})
	sess.SetExpiresAt(fosite.AccessToken, token.ExpiresAt)

	return newFositeRequest(token.RequestID, token.CreatedAt, client, sess, token.Scopes, nil), nil
}

func (s *Storage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.getTokens(ctx).DeleteByAccessToken(ctx, signature)
}

func (s *Storage) CreateRefreshTokenSession(ctx context.Context, signature string, _ string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}

	return s.getTokens(ctx).Create(ctx, domain.Token{
		ID:           uuid.New().String(),
		RequestID:    request.GetID(),
		ClientID:     request.GetClient().GetID(),
		UserID:       sess.GetSubject(),
		RefreshToken: signature,
		Scopes:       request.GetGrantedScopes(),
		ExpiresAt:    sess.GetExpiresAt(fosite.RefreshToken),
	})
}

func (s *Storage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return nil
}

func (s *Storage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	token, err := s.getTokens(ctx).GetByRefreshToken(ctx, signature)
	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, token.ClientID)
	if err != nil {
		return nil, err
	}

	sess := NewSession(token.UserID, time.Time{})
	sess.SetExpiresAt(fosite.RefreshToken, token.ExpiresAt)

	return newFositeRequest(token.RequestID, token.CreatedAt, client, sess, token.Scopes, nil), nil
}

func (s *Storage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.getTokens(ctx).DeleteByRefreshToken(ctx, signature)
}

func (s *Storage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.getTokens(ctx).DeleteByRequestID(ctx, requestID)
}

func (s *Storage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.getTokens(ctx).DeleteByRequestID(ctx, requestID)
}
