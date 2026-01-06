package v1

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
)

// TODO: Implement after sqlc regeneration

func (r *MariaDBRepository) CreateClient(_ context.Context, _ repository.CreateClientParams) (domain.Client, error) {
	return domain.Client{}, errors.New("not implemented")
}

func (r *MariaDBRepository) GetClient(_ context.Context, _ domain.ClientID) (domain.Client, error) {
	return domain.Client{}, errors.New("not implemented")
}

func (r *MariaDBRepository) ListClients(_ context.Context) ([]domain.Client, error) {
	return nil, errors.New("not implemented")
}

func (r *MariaDBRepository) UpdateClient(_ context.Context, _ domain.ClientID, _ repository.UpdateClientParams) (domain.Client, error) {
	return domain.Client{}, errors.New("not implemented")
}

func (r *MariaDBRepository) UpdateClientSecret(_ context.Context, _ domain.ClientID, _ *string) (domain.Client, error) {
	return domain.Client{}, errors.New("not implemented")
}

func (r *MariaDBRepository) DeleteClient(_ context.Context, _ domain.ClientID) error {
	return errors.New("not implemented")
}
