package repository

import (
	"context"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type CreateClientParams struct {
	ID           domain.ClientID
	SecretHash   *string
	Name         string
	Type         domain.ClientType
	RedirectURIs []string
}

type UpdateClientParams struct {
	Name         string
	Type         domain.ClientType
	RedirectURIs []string
}

type OIDCClientRepository interface {
	CreateOIDCClient(ctx context.Context, params CreateClientParams) (domain.Client, error)
	GetOIDCClient(ctx context.Context, id domain.ClientID) (domain.Client, error)
	ListOIDCClients(ctx context.Context) ([]domain.Client, error)
	UpdateOIDCClient(ctx context.Context, id domain.ClientID, params UpdateClientParams) (domain.Client, error)
	UpdateOIDCClientSecret(ctx context.Context, id domain.ClientID, secretHash *string) (domain.Client, error)
	DeleteOIDCClient(ctx context.Context, id domain.ClientID) error
}
