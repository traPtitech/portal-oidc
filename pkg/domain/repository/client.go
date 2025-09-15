package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type OIDCClientRepository interface {
	CreateOIDCClient(ctx context.Context, id uuid.UUID, userID domain.TrapID, typ domain.ClientType, name string, desc string, secret string, redirectURIs []string) (domain.Client, error)
	GetOIDCClient(ctx context.Context, id domain.ClientID) (domain.Client, error)
	ListOIDCClientsByUser(ctx context.Context, userID domain.TrapID) ([]domain.Client, error)
	UpdateOIDCClient(ctx context.Context, id domain.ClientID, userID domain.TrapID, typ domain.ClientType, name string, desc string, redirectURIs []string) (domain.Client, error)
	UpdateOIDCClientSecret(ctx context.Context, id domain.ClientID, secret string) (domain.Client, error)
	DeleteOIDCClient(ctx context.Context, id domain.ClientID) error
	GetBlacklistJTI(ctx context.Context, jti string) (domain.BlacklistedJTI, error)
	DeleteOldBlacklistJTI(ctx context.Context) error
	CreateBlacklistJTI(ctx context.Context, jti string, after time.Time) error
	CreateAccessTokenSession(ctx context.Context, req *fosite.Request) error
	GetAccessTokenSession(ctx context.Context, signature string) (*fosite.Request, error)
}
