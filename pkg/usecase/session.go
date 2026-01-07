package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
)

const (
	sessionExpiry      = 24 * time.Hour
	loginSessionExpiry = 10 * time.Minute
)

func (u *UseCase) CreateSession(ctx context.Context, userID domain.TrapID, clientID domain.ClientID, scopes []string) (domain.Session, error) {
	return u.repo.CreateSession(ctx, repository.CreateSessionParams{
		ID:            domain.SessionID(uuid.New()),
		UserID:        userID,
		ClientID:      clientID,
		AllowedScopes: scopes,
		ExpiresAt:     time.Now().Add(sessionExpiry),
	})
}

func (u *UseCase) GetSession(ctx context.Context, sessionID domain.SessionID) (domain.Session, error) {
	return u.repo.GetSession(ctx, sessionID)
}

func (u *UseCase) CreateLoginSession(ctx context.Context, forms string, scopes []string, userID domain.TrapID, clientID domain.ClientID) (domain.LoginSession, error) {
	return u.repo.CreateLoginSession(ctx, repository.CreateLoginSessionParams{
		ID:            domain.LoginSessionID(uuid.New()),
		Forms:         forms,
		AllowedScopes: scopes,
		UserID:        userID,
		ClientID:      clientID,
		ExpiresAt:     time.Now().Add(loginSessionExpiry),
	})
}

func (u *UseCase) GetLoginSession(ctx context.Context, loginSessionID domain.LoginSessionID) (domain.LoginSession, error) {
	return u.repo.GetLoginSession(ctx, loginSessionID)
}

func (u *UseCase) DeleteLoginSession(ctx context.Context, loginSessionID domain.LoginSessionID) error {
	return u.repo.DeleteLoginSession(ctx, loginSessionID)
}
