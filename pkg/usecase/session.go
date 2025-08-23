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
