package usecase

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/random"
)

func (u *UseCase) CreateClient(ctx context.Context, userID domain.TrapID, typ domain.ClientType, name string, desc string, redirectURIs []string) (domain.Client, error) {
	id := uuid.New()
	secret := random.GenerateRandomString(domain.DefaultSecretLength)

	client, err := u.repo.CreateOIDCClient(ctx, id, userID, typ, name, desc, secret, redirectURIs)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to create client")
	}

	return client, nil
}

func (u *UseCase) ListClientsByUser(ctx context.Context, userID domain.TrapID) ([]domain.Client, error) {
	clients, err := u.repo.ListOIDCClientsByUser(ctx, userID)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list clients")
	}

	return clients, nil
}

func (u *UseCase) UpdateClient(ctx context.Context, id domain.ClientID, userID domain.TrapID, typ domain.ClientType, name string, desc string, redirectURIs []string) (domain.Client, error) {
	client, err := u.repo.GetOIDCClient(ctx, id)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	if client.UserID != userID {
		return domain.Client{}, errors.New("Client does not belong to the user")
	}

	newclient, err := u.repo.UpdateOIDCClient(ctx, id, userID, typ, name, desc, redirectURIs)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to update client")
	}

	return newclient, nil
}

func (u *UseCase) UpdateClientSecret(ctx context.Context, userID domain.TrapID, id domain.ClientID) (domain.Client, error) {
	client, err := u.repo.GetOIDCClient(ctx, id)
	secret := random.GenerateRandomString(domain.DefaultSecretLength)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	if client.UserID != userID {
		return domain.Client{}, errors.New("Client does not belong to the user")
	}

	newclient, err := u.repo.UpdateOIDCClientSecret(ctx, id, secret)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to update client secret")
	}

	return newclient, nil
}

func (u *UseCase) DeleteClient(ctx context.Context, userID domain.TrapID, id domain.ClientID) error {
	client, err := u.repo.GetOIDCClient(ctx, id)
	if err != nil {
		return errors.Wrap(err, "Failed to get client")
	}

	if client.UserID != userID {
		return errors.New("Client does not belong to the user")
	}

	err = u.repo.DeleteOIDCClient(ctx, id)
	if err != nil {
		return errors.Wrap(err, "Failed to delete client")
	}

	return nil
}
