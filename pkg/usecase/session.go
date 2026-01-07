package usecase

import (
	"context"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

func (u *UseCase) CreateSession(ctx context.Context, userID domain.TrapID, clientID domain.ClientID, scopes []string) (domain.Session, error) {
	// TODO: DBに保存する
	return domain.Session{}, nil
}

func (u *UseCase) GetSession(ctx context.Context, sessionID domain.SessionID) (domain.Session, error) {
	// TODO: DBからとってくるときにExpiresAtでフィルターする
	return domain.Session{}, nil
}

func (u *UseCase) CreateLoginSession(ctx context.Context, forms string) (domain.LoginSession, error) {
	// TODO: DBに保存する
	return domain.LoginSession{}, nil
}

func (u *UseCase) GetLoginSession(ctx context.Context, loginSessionID domain.LoginSessionID) (domain.LoginSession, error) {
	// TODO: DBからとってくるときにExpiresAtでフィルターする
	return domain.LoginSession{}, nil
}
