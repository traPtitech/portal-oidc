package usecase

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

func (u *UseCase) CreateClient(ctx context.Context, userID domain.UserID, typ domain.ClientType, name string, desc string, secret string, redirectURIs []string) (domain.Client, error) {
	id := uuid.New()

	client, err := u.repo.CreateOIDCClient(ctx, id, userID, typ, name, desc, secret, redirectURIs)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to create client")
	}

	return client, nil
}

func (u *UseCase) GetClient(ctx context.Context, id domain.ClientID) (domain.Client, error) {
	client, err := u.repo.GetOIDCClient(ctx, id)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	return client, nil
}

func (u *UseCase) ListClientsByUser(ctx context.Context, userID domain.UserID) ([]domain.Client, error) {
	clients, err := u.repo.ListOIDCClientsByUser(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list clients")
	}

	return clients, nil
}

func (u *UseCase) UpdateClient(ctx context.Context, id domain.ClientID, userID domain.UserID, typ domain.ClientType, name string, desc string, redirectURIs []string) (domain.Client, error) {
	client, err := u.repo.UpdateOIDCClient(ctx, id, userID, typ, name, desc, redirectURIs)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to update client")
	}

	return client, nil
}

func (u *UseCase) UpdateClientSecret(ctx context.Context, id domain.ClientID, secret string) (domain.Client, error) {
	client, err := u.repo.UpdateOIDCClientSecret(ctx, id, secret)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to update client secret")
	}

	return client, nil
}

func (u *UseCase) DeleteClient(ctx context.Context, id domain.ClientID) error {
	err := u.repo.DeleteOIDCClient(ctx, id)
	if err != nil {
		return errors.Wrap(err, "Failed to delete client")
	}

	return nil
}
