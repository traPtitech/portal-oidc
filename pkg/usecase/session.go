package usecase

import (
	"context"
	"database/sql"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

// Session (認証済みユーザー)

func (u *UseCase) CreateSession(ctx context.Context, userID domain.TrapID, userAgent, ipAddress string) (domain.Session, error) {
	now := time.Now()
	sess := domain.Session{
		ID:           domain.SessionID(uuid.New()),
		UserID:       userID,
		UserAgent:    userAgent,
		IPAddress:    ipAddress,
		AuthTime:     now,
		LastActiveAt: now,
		ExpiresAt:    now.Add(24 * time.Hour),
		CreatedAt:    now,
	}

	if err := u.repo.CreateSession(ctx, sess); err != nil {
		return domain.Session{}, errors.Wrap(err, "failed to create session")
	}

	return sess, nil
}

func (u *UseCase) GetSession(ctx context.Context, sessionID domain.SessionID) (domain.Session, error) {
	sess, err := u.repo.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Session{}, ErrSessionNotFound
		}
		return domain.Session{}, errors.Wrap(err, "failed to get session")
	}

	if time.Now().After(sess.ExpiresAt) {
		return domain.Session{}, ErrSessionExpired
	}

	return sess, nil
}

func (u *UseCase) DeleteSession(ctx context.Context, sessionID domain.SessionID) error {
	return u.repo.DeleteSession(ctx, sessionID)
}

// AuthorizationRequest (OAuth認可リクエスト一時保存)

func (u *UseCase) CreateAuthorizationRequest(ctx context.Context, req domain.AuthorizationRequest) (domain.AuthorizationRequest, error) {
	now := time.Now()
	req.ID = domain.AuthorizationRequestID(uuid.New())
	req.ExpiresAt = now.Add(15 * time.Minute)
	req.CreatedAt = now

	if err := u.repo.CreateAuthorizationRequest(ctx, req); err != nil {
		return domain.AuthorizationRequest{}, errors.Wrap(err, "failed to create authorization request")
	}

	return req, nil
}

func (u *UseCase) GetAuthorizationRequest(ctx context.Context, id domain.AuthorizationRequestID) (domain.AuthorizationRequest, error) {
	req, err := u.repo.GetAuthorizationRequest(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AuthorizationRequest{}, ErrSessionNotFound
		}
		return domain.AuthorizationRequest{}, errors.Wrap(err, "failed to get authorization request")
	}

	if time.Now().After(req.ExpiresAt) {
		return domain.AuthorizationRequest{}, ErrSessionExpired
	}

	return req, nil
}

func (u *UseCase) UpdateAuthorizationRequestUserID(ctx context.Context, id domain.AuthorizationRequestID, userID domain.TrapID) error {
	return u.repo.UpdateAuthorizationRequestUserID(ctx, id, userID)
}

func (u *UseCase) DeleteAuthorizationRequest(ctx context.Context, id domain.AuthorizationRequestID) error {
	return u.repo.DeleteAuthorizationRequest(ctx, id)
}
