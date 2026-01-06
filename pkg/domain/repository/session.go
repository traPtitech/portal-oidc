package repository

import (
	"context"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type SessionRepository interface {
	// Session (認証済みユーザー)
	CreateSession(ctx context.Context, sess domain.Session) error
	GetSession(ctx context.Context, id domain.SessionID) (domain.Session, error)
	DeleteSession(ctx context.Context, id domain.SessionID) error

	// AuthorizationRequest (認可リクエスト一時保存)
	CreateAuthorizationRequest(ctx context.Context, req domain.AuthorizationRequest) error
	GetAuthorizationRequest(ctx context.Context, id domain.AuthorizationRequestID) (domain.AuthorizationRequest, error)
	UpdateAuthorizationRequestUserID(ctx context.Context, id domain.AuthorizationRequestID, userID domain.TrapID) error
	DeleteAuthorizationRequest(ctx context.Context, id domain.AuthorizationRequestID) error

	// AuthorizationCode (認可コード)
	CreateAuthorizationCode(ctx context.Context, code domain.AuthorizationCode) error
	GetAuthorizationCode(ctx context.Context, code string) (domain.AuthorizationCode, error)
	MarkAuthorizationCodeUsed(ctx context.Context, code string) error
	DeleteAuthorizationCode(ctx context.Context, code string) error
}
