package v1

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
)

// TODO: Implement after sqlc regeneration

func (r *MariaDBRepository) CreateOIDCClient(_ context.Context, _ repository.CreateClientParams) (domain.Client, error) {
	return domain.Client{}, errors.New("not implemented")
}

func (r *MariaDBRepository) GetOIDCClient(_ context.Context, _ domain.ClientID) (domain.Client, error) {
	return domain.Client{}, errors.New("not implemented")
}

func (r *MariaDBRepository) ListOIDCClients(_ context.Context) ([]domain.Client, error) {
	return nil, errors.New("not implemented")
}

func (r *MariaDBRepository) UpdateOIDCClient(_ context.Context, _ domain.ClientID, _ repository.UpdateClientParams) (domain.Client, error) {
	return domain.Client{}, errors.New("not implemented")
}

func (r *MariaDBRepository) UpdateOIDCClientSecret(_ context.Context, _ domain.ClientID, _ *string) (domain.Client, error) {
	return domain.Client{}, errors.New("not implemented")
}

func (r *MariaDBRepository) DeleteOIDCClient(_ context.Context, _ domain.ClientID) error {
	return errors.New("not implemented")
}
