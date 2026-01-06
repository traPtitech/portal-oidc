package usecase

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrConsentNotFound = errors.New("consent not found")
)

// Session (ログインセッション)

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

func (u *UseCase) RevokeSession(ctx context.Context, sessionID domain.SessionID) error {
	return u.repo.RevokeSession(ctx, sessionID)
}

// UserConsent (ユーザー同意)

func (u *UseCase) GetOrCreateUserConsent(ctx context.Context, userID domain.TrapID, clientID domain.ClientID, scopes []string) (domain.UserConsent, error) {
	consent, err := u.repo.GetUserConsent(ctx, userID, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 同意が存在しない場合は新規作成
			now := time.Now()
			consent = domain.UserConsent{
				ID:        domain.UserConsentID(uuid.New()),
				UserID:    userID,
				ClientID:  clientID,
				Scopes:    scopes,
				GrantedAt: now,
			}
			if err := u.repo.CreateUserConsent(ctx, consent); err != nil {
				return domain.UserConsent{}, errors.Wrap(err, "failed to create user consent")
			}
			return consent, nil
		}
		return domain.UserConsent{}, errors.Wrap(err, "failed to get user consent")
	}

	return consent, nil
}

func (u *UseCase) GetUserConsent(ctx context.Context, userID domain.TrapID, clientID domain.ClientID) (domain.UserConsent, error) {
	consent, err := u.repo.GetUserConsent(ctx, userID, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.UserConsent{}, ErrConsentNotFound
		}
		return domain.UserConsent{}, errors.Wrap(err, "failed to get user consent")
	}
	return consent, nil
}

func (u *UseCase) UpdateUserConsentScopes(ctx context.Context, userID domain.TrapID, clientID domain.ClientID, newScopes []string) error {
	consent, err := u.repo.GetUserConsent(ctx, userID, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 同意が存在しない場合は新規作成
			now := time.Now()
			consent = domain.UserConsent{
				ID:        domain.UserConsentID(uuid.New()),
				UserID:    userID,
				ClientID:  clientID,
				Scopes:    newScopes,
				GrantedAt: now,
			}
			return u.repo.CreateUserConsent(ctx, consent)
		}
		return errors.Wrap(err, "failed to get user consent")
	}

	// 既存のスコープに新しいスコープを追加
	mergedScopes := consent.Scopes
	for _, s := range newScopes {
		if !slices.Contains(mergedScopes, s) {
			mergedScopes = append(mergedScopes, s)
		}
	}

	return u.repo.UpdateUserConsentScopes(ctx, userID, clientID, mergedScopes, time.Now())
}

// LoginSession (OAuth認可フロー一時状態)

func (u *UseCase) CreateLoginSession(ctx context.Context, clientID string, redirectURI string, formData string, scopes []string) (domain.LoginSession, error) {
	clientUUID, err := uuid.Parse(clientID)
	if err != nil {
		return domain.LoginSession{}, errors.Wrap(err, "invalid client ID")
	}

	now := time.Now()
	sess := domain.LoginSession{
		ID:          domain.LoginSessionID(uuid.New()),
		ClientID:    domain.ClientID(clientUUID),
		RedirectURI: redirectURI,
		FormData:    formData,
		Scopes:      scopes,
		CreatedAt:   now,
		ExpiresAt:   now.Add(10 * time.Minute),
	}

	if err := u.repo.CreateLoginSession(ctx, sess); err != nil {
		return domain.LoginSession{}, errors.Wrap(err, "failed to create login session")
	}

	return sess, nil
}

func (u *UseCase) GetLoginSession(ctx context.Context, loginSessionID domain.LoginSessionID) (domain.LoginSession, error) {
	sess, err := u.repo.GetLoginSession(ctx, loginSessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.LoginSession{}, ErrSessionNotFound
		}
		return domain.LoginSession{}, errors.Wrap(err, "failed to get login session")
	}

	if time.Now().After(sess.ExpiresAt) {
		return domain.LoginSession{}, ErrSessionExpired
	}

	return sess, nil
}

func (u *UseCase) DeleteLoginSession(ctx context.Context, loginSessionID domain.LoginSessionID) error {
	return u.repo.DeleteLoginSession(ctx, loginSessionID)
}
