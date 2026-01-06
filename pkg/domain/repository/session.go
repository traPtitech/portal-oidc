package repository

import (
	"context"
	"time"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type SessionRepository interface {
	// Session (ログインセッション)
	CreateSession(ctx context.Context, sess domain.Session) error
	GetSession(ctx context.Context, id domain.SessionID) (domain.Session, error)
	UpdateSessionLastActive(ctx context.Context, id domain.SessionID, lastActiveAt time.Time) error
	RevokeSession(ctx context.Context, id domain.SessionID) error
	ListSessionsByUser(ctx context.Context, userID domain.TrapID) ([]domain.Session, error)

	// UserConsent (ユーザー同意情報)
	CreateUserConsent(ctx context.Context, consent domain.UserConsent) error
	GetUserConsent(ctx context.Context, userID domain.TrapID, clientID domain.ClientID) (domain.UserConsent, error)
	UpdateUserConsentScopes(ctx context.Context, userID domain.TrapID, clientID domain.ClientID, scopes []string, grantedAt time.Time) error
	RevokeUserConsent(ctx context.Context, userID domain.TrapID, clientID domain.ClientID) error

	// LoginSession (OAuth認可フロー一時状態)
	CreateLoginSession(ctx context.Context, sess domain.LoginSession) error
	GetLoginSession(ctx context.Context, id domain.LoginSessionID) (domain.LoginSession, error)
	DeleteLoginSession(ctx context.Context, id domain.LoginSessionID) error
}
