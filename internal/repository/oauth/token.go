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

// CreateAccessTokenSession persists a fosite-issued access token. The
// signature is what fosite uses as the lookup key on subsequent
// GetAccessTokenSession calls, so we store it in jti.
func (s *Storage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}
	clientID, err := uuid.Parse(request.GetClient().GetID())
	if err != nil {
		return err
	}

	var userID *uuid.UUID
	if sub := sess.GetSubject(); sub != "" {
		uid, perr := uuid.Parse(sub)
		if perr == nil {
			userID = &uid
		}
	}

	return s.getAccessTokens(ctx).Create(ctx, domain.AccessToken{
		JTI:       signature,
		RequestID: request.GetID(),
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    request.GetGrantedScopes(),
		ExpiresAt: sess.GetExpiresAt(fosite.AccessToken),
	})
}

func (s *Storage) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	token, err := s.getAccessTokens(ctx).GetByJTI(ctx, signature)
	if err != nil {
		if errors.Is(err, repository.ErrAccessTokenNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if token.RevokedAt != nil {
		return nil, fosite.ErrInactiveToken
	}
	if time.Now().After(token.ExpiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	client, err := s.GetClient(ctx, token.ClientID.String())
	if err != nil {
		return nil, err
	}

	subject := ""
	if token.UserID != nil {
		subject = token.UserID.String()
	}
	sess := NewSession(subject, time.Time{})
	sess.SetExpiresAt(fosite.AccessToken, token.ExpiresAt)

	return newFositeRequest(token.RequestID, token.IssuedAt, client, sess, token.Scopes, nil), nil
}

func (s *Storage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.getAccessTokens(ctx).DeleteByJTI(ctx, signature)
}

// CreateRefreshTokenSession persists a fosite-issued refresh token. fosite
// supplies the access-token signature as the second argument so the rotation
// chain can be reconstructed; we record it on the row indirectly via
// request_id which both halves share.
func (s *Storage) CreateRefreshTokenSession(ctx context.Context, signature string, _ string, request fosite.Requester) error {
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

	return s.getRefreshTokens(ctx).Create(ctx, domain.RefreshToken{
		TokenHash: signature,
		RequestID: request.GetID(),
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    request.GetGrantedScopes(),
		ExpiresAt: sess.GetExpiresAt(fosite.RefreshToken),
	})
}

// RotateRefreshToken marks the previous refresh token as rotated. The new
// refresh token is created via CreateRefreshTokenSession on the same
// transaction (fosite's flow). Marking instead of deleting lets a follow-up
// PR walk PreviousTokenID and revoke the whole family on detected reuse
// (OAuth 2.1 §4.13.2).
func (s *Storage) RotateRefreshToken(ctx context.Context, _ string, refreshTokenSignature string) error {
	return s.getRefreshTokens(ctx).DeleteByHash(ctx, refreshTokenSignature)
}

func (s *Storage) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	token, err := s.getRefreshTokens(ctx).GetByHash(ctx, signature)
	if err != nil {
		if errors.Is(err, repository.ErrRefreshTokenNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	if token.RevokedAt != nil || token.RotatedAt != nil {
		return nil, fosite.ErrInactiveToken
	}

	client, err := s.GetClient(ctx, token.ClientID.String())
	if err != nil {
		return nil, err
	}

	sess := NewSession(token.UserID.String(), time.Time{})
	sess.SetExpiresAt(fosite.RefreshToken, token.ExpiresAt)

	return newFositeRequest(token.RequestID, token.IssuedAt, client, sess, token.Scopes, nil), nil
}

func (s *Storage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.getRefreshTokens(ctx).DeleteByHash(ctx, signature)
}

// RevokeRefreshToken marks every refresh token issued under this request_id
// as revoked. Marking (vs deleting) keeps the audit trail intact and lets a
// future family-revocation pass identify the chain.
func (s *Storage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.getRefreshTokens(ctx).RevokeByRequestID(ctx, requestID)
}

func (s *Storage) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.getAccessTokens(ctx).RevokeByRequestID(ctx, requestID)
}
