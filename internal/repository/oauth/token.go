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

// CreateAccessTokenSession persists a fosite-issued access token keyed by its
// signature, which fosite uses as the lookup key on subsequent
// GetAccessTokenSession calls.
func (s *Storage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	sess, ok := request.GetSession().(*Session)
	if !ok {
		return errors.New("invalid session type")
	}
	clientID, err := uuid.Parse(request.GetClient().GetID())
	if err != nil {
		return err
	}

	// An empty subject is stored as NULL; a non-empty one must be a user UUID.
	var userID *uuid.UUID
	if sub := sess.GetSubject(); sub != "" {
		uid, err := uuid.Parse(sub)
		if err != nil {
			return err
		}
		userID = &uid
	}

	return s.getAccessTokens(ctx).Create(ctx, domain.AccessToken{
		Signature: signature,
		RequestID: request.GetID(),
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    request.GetGrantedScopes(),
		ExpiresAt: sess.GetExpiresAt(fosite.AccessToken),
	})
}

func (s *Storage) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	token, err := s.getAccessTokens(ctx).GetBySignature(ctx, signature)
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
	return s.getAccessTokens(ctx).DeleteBySignature(ctx, signature)
}

// CreateRefreshTokenSession persists a fosite-issued refresh token. The
// access-token signature fosite passes as the second argument is not stored;
// the two halves are linked only through the shared request_id, which
// identifies the whole token family rather than a specific access token.
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
		Signature: signature,
		RequestID: request.GetID(),
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    request.GetGrantedScopes(),
		ExpiresAt: sess.GetExpiresAt(fosite.RefreshToken),
	})
}

// RotateRefreshToken marks the previous refresh token as rotated (instead of
// deleting it) so that a replay surfaces as fosite.ErrInactiveToken and fosite
// revokes the whole family. Access tokens issued earlier under the same
// request_id are revoked; the replacement pair is created afterwards in the
// same transaction.
//
// fosite loads the refresh token outside this transaction, so two concurrent
// requests with the same token can both get here. Only one of them can match
// the rotated_at IS NULL guard; the other is reported as
// fosite.ErrSerializationFailure so fosite rolls back and asks for a retry.
func (s *Storage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	if err := s.getRefreshTokens(ctx).RotateBySignature(ctx, refreshTokenSignature); err != nil {
		if errors.Is(err, repository.ErrRefreshTokenNotRotated) {
			return fosite.ErrSerializationFailure
		}
		return err
	}
	return s.getAccessTokens(ctx).RevokeByRequestID(ctx, requestID)
}

func (s *Storage) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	token, err := s.getRefreshTokens(ctx).GetBySignature(ctx, signature)
	if err != nil {
		if errors.Is(err, repository.ErrRefreshTokenNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, token.ClientID.String())
	if err != nil {
		return nil, err
	}

	sess := NewSession(token.UserID.String(), time.Time{})
	sess.SetExpiresAt(fosite.RefreshToken, token.ExpiresAt)
	req := newFositeRequest(token.RequestID, token.IssuedAt, client, sess, token.Scopes, nil)

	// fosite's reuse handling calls GetID() on the returned requester, so it
	// must accompany ErrInactiveToken.
	if token.RevokedAt != nil || token.RotatedAt != nil {
		return req, fosite.ErrInactiveToken
	}

	return req, nil
}

func (s *Storage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.getRefreshTokens(ctx).DeleteBySignature(ctx, signature)
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
