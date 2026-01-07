package repository

import (
	"context"
	"time"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type CreateSessionParams struct {
	ID            domain.SessionID
	UserID        domain.TrapID
	ClientID      domain.ClientID
	AllowedScopes []string
	ExpiresAt     time.Time
}

type CreateLoginSessionParams struct {
	ID            domain.LoginSessionID
	Forms         string
	AllowedScopes []string
	UserID        domain.TrapID
	ClientID      domain.ClientID
	ExpiresAt     time.Time
}

type SessionRepository interface {
	CreateSession(ctx context.Context, params CreateSessionParams) (domain.Session, error)
	GetSession(ctx context.Context, id domain.SessionID) (domain.Session, error)
	DeleteSession(ctx context.Context, id domain.SessionID) error
	DeleteExpiredSessions(ctx context.Context) error

	CreateLoginSession(ctx context.Context, params CreateLoginSessionParams) (domain.LoginSession, error)
	GetLoginSession(ctx context.Context, id domain.LoginSessionID) (domain.LoginSession, error)
	DeleteLoginSession(ctx context.Context, id domain.LoginSessionID) error
	DeleteExpiredLoginSessions(ctx context.Context) error
}
