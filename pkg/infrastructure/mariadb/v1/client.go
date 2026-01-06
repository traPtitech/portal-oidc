package v1

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
	mariadb "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1/gen"
)

func (r *MariaDBRepository) CreateClient(ctx context.Context, params repository.CreateClientParams) (domain.Client, error) {
	redirectURIs, err := json.Marshal(params.RedirectURIs)
	if err != nil {
		return domain.Client{}, err
	}

	err = r.q.CreateClient(ctx, mariadb.CreateClientParams{
		ClientID:         uuid.UUID(params.ID).String(),
		ClientSecretHash: toNullString(params.SecretHash),
		Name:             params.Name,
		ClientType:       params.Type.String(),
		RedirectUris:     redirectURIs,
	})
	if err != nil {
		return domain.Client{}, err
	}

	return r.GetClient(ctx, params.ID)
}

func (r *MariaDBRepository) GetClient(ctx context.Context, id domain.ClientID) (domain.Client, error) {
	c, err := r.q.GetClient(ctx, uuid.UUID(id).String())
	if err != nil {
		return domain.Client{}, err
	}
	return toDomainClient(c)
}

func (r *MariaDBRepository) ListClients(ctx context.Context) ([]domain.Client, error) {
	clients, err := r.q.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]domain.Client, 0, len(clients))
	for _, c := range clients {
		dc, err := toDomainClient(c)
		if err != nil {
			return nil, err
		}
		result = append(result, dc)
	}
	return result, nil
}

func (r *MariaDBRepository) UpdateClient(ctx context.Context, id domain.ClientID, params repository.UpdateClientParams) (domain.Client, error) {
	redirectURIs, err := json.Marshal(params.RedirectURIs)
	if err != nil {
		return domain.Client{}, err
	}

	err = r.q.UpdateClient(ctx, mariadb.UpdateClientParams{
		ClientID:     uuid.UUID(id).String(),
		Name:         params.Name,
		ClientType:   params.Type.String(),
		RedirectUris: redirectURIs,
	})
	if err != nil {
		return domain.Client{}, err
	}

	return r.GetClient(ctx, id)
}

func (r *MariaDBRepository) UpdateClientSecret(ctx context.Context, id domain.ClientID, secretHash *string) (domain.Client, error) {
	err := r.q.UpdateClientSecret(ctx, mariadb.UpdateClientSecretParams{
		ClientID:         uuid.UUID(id).String(),
		ClientSecretHash: toNullString(secretHash),
	})
	if err != nil {
		return domain.Client{}, err
	}

	return r.GetClient(ctx, id)
}

func (r *MariaDBRepository) DeleteClient(ctx context.Context, id domain.ClientID) error {
	return r.q.DeleteClient(ctx, uuid.UUID(id).String())
}

func toDomainClient(c mariadb.Client) (domain.Client, error) {
	clientID, err := uuid.Parse(c.ClientID)
	if err != nil {
		return domain.Client{}, err
	}

	clientType, err := domain.ParseClientType(c.ClientType)
	if err != nil {
		return domain.Client{}, err
	}

	var redirectURIs []string
	if err := json.Unmarshal(c.RedirectUris, &redirectURIs); err != nil {
		return domain.Client{}, err
	}

	return domain.Client{
		ID:           domain.ClientID(clientID),
		SecretHash:   fromNullString(c.ClientSecretHash),
		Name:         c.Name,
		Type:         clientType,
		RedirectURIs: redirectURIs,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}, nil
}

func toNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func fromNullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}
