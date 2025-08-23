package v1

import (
	"context"
	"encoding/json"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	mariadb "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1/gen"
)

func convertToDomainClient(client *mariadb.Client) (domain.Client, error) {
	redirectURIs := []string{}
	err := json.Unmarshal(client.RedirectUris, &redirectURIs)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to unmarshal redirect uris")
	}

	clientID, err := uuid.Parse(client.ID)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to parse client id")
	}

	return domain.Client{
		ID:           domain.ClientID(clientID),
		UserID:       domain.TrapID(client.UserID),
		Type:         domain.ClientType(client.Type),
		Name:         client.Name,
		Description:  client.Description,
		Secret:       client.SecretKey,
		RedirectURIs: redirectURIs,
	}, nil
}

func (r *MariaDBRepository) CreateOIDCClient(ctx context.Context, id uuid.UUID, userID domain.TrapID, typ domain.ClientType, name string, desc string, secret string, redirectURIs []string) (domain.Client, error) {
	encURLs, err := json.Marshal(redirectURIs)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to marshal redirect uris")
	}

	err = r.q.CreateClient(ctx, mariadb.CreateClientParams{
		ID:           id.String(),
		UserID:       userID.String(),
		Type:         typ.String(),
		Name:         name,
		Description:  desc,
		SecretKey:    secret,
		RedirectUris: encURLs,
	})

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to create client")
	}

	client, err := r.q.GetClient(ctx, id.String())
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	return convertToDomainClient(&client)
}

func (r *MariaDBRepository) GetOIDCClient(ctx context.Context, id domain.ClientID) (domain.Client, error) {
	client, err := r.q.GetClient(ctx, id.String())

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	return convertToDomainClient(&client)
}

func (r *MariaDBRepository) ListOIDCClientsByUser(ctx context.Context, userID domain.TrapID) ([]domain.Client, error) {

	clients, err := r.q.ListClientsByUserID(ctx, userID.String())

	if err != nil {
		return nil, errors.Wrap(err, "Failed to get clients")
	}

	clientList := make([]domain.Client, len(clients))
	for i, client := range clients {

		c, err := convertToDomainClient(&client)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to convert client")
		}

		clientList[i] = c
	}

	return clientList, nil
}

func (r *MariaDBRepository) UpdateOIDCClient(ctx context.Context, id domain.ClientID, userID domain.TrapID, typ domain.ClientType, name string, desc string, redirectURIs []string) (domain.Client, error) {
	encURLs, err := json.Marshal(redirectURIs)
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to marshal redirect uris")
	}

	err = r.q.UpdateClient(ctx, mariadb.UpdateClientParams{
		ID:           id.String(),
		Type:         typ.String(),
		Name:         name,
		Description:  desc,
		RedirectUris: encURLs,
	})

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to update client")
	}

	newclient, err := r.q.GetClient(ctx, id.String())

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	return convertToDomainClient(&newclient)
}

func (r *MariaDBRepository) UpdateOIDCClientSecret(ctx context.Context, id domain.ClientID, secret string) (domain.Client, error) {
	err := r.q.UpdateClientSecret(ctx, mariadb.UpdateClientSecretParams{
		ID:        id.String(),
		SecretKey: secret,
	})

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to update client secret")
	}

	newclient, err := r.q.GetClient(ctx, id.String())

	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to get client")
	}

	return convertToDomainClient(&newclient)

}

func (r *MariaDBRepository) DeleteOIDCClient(ctx context.Context, id domain.ClientID) error {
	err := r.q.DeleteClient(ctx, id.String())

	if err != nil {
		return errors.Wrap(err, "Failed to delete client")
	}

	return nil

}
