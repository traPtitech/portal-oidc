package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type OIDCClientRepository interface {
	CreateOIDCClient(ctx context.Context, id uuid.UUID, userID domain.UserID, typ domain.ClientType, name string, desc string, secret string, redirectURIs []string) (domain.Client, error)
	GetOIDCClient(ctx context.Context, id domain.ClientID) (domain.Client, error)
	ListOIDCClientsByUser(ctx context.Context, userID domain.UserID) ([]domain.Client, error)
	UpdateOIDCClient(ctx context.Context, id domain.ClientID, userID domain.UserID, typ domain.ClientType, name string, desc string, redirectURIs []string) (domain.Client, error)
	UpdateOIDCClientSecret(ctx context.Context, id domain.ClientID, secret string) (domain.Client, error)
	DeleteOIDCClient(ctx context.Context, id domain.ClientID) error
}
