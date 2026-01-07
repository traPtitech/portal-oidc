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

type ClientRepository interface {
	CreateClient(ctx context.Context, params CreateClientParams) (domain.Client, error)
	GetClient(ctx context.Context, id domain.ClientID) (domain.Client, error)
	ListClients(ctx context.Context) ([]domain.Client, error)
	UpdateClient(ctx context.Context, id domain.ClientID, params UpdateClientParams) (domain.Client, error)
	UpdateClientSecret(ctx context.Context, id domain.ClientID, secretHash *string) (domain.Client, error)
	DeleteClient(ctx context.Context, id domain.ClientID) error
}
