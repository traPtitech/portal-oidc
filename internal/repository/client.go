package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrClientNotFound = errors.New("client not found")

type ClientRepository interface {
	Create(ctx context.Context, client *domain.Client, secretHash string) error
	Get(ctx context.Context, clientID uuid.UUID) (*domain.Client, error)
	GetWithSecretHash(ctx context.Context, clientID uuid.UUID) (*domain.Client, string, error)
	List(ctx context.Context) ([]*domain.Client, error)
	Update(ctx context.Context, client *domain.Client) error
	UpdateSecret(ctx context.Context, clientID uuid.UUID, secretHash string) error
	Delete(ctx context.Context, clientID uuid.UUID) error
}

type clientRepository struct {
	queries *oidc.Queries
}

func NewClientRepository(queries *oidc.Queries) ClientRepository {
	return &clientRepository{queries: queries}
}

func (r *clientRepository) Create(ctx context.Context, client *domain.Client, secretHash string) error {
	redirectURIsJSON, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return err
	}

	return r.queries.CreateClient(ctx, oidc.CreateClientParams{
		ClientID: client.ClientID.String(),
		ClientSecretHash: sql.NullString{
			String: secretHash,
			Valid:  secretHash != "",
		},
		Name:         client.Name,
		ClientType:   string(client.ClientType),
		RedirectUris: redirectURIsJSON,
	})
}

func (r *clientRepository) Get(ctx context.Context, clientID uuid.UUID) (*domain.Client, error) {
	dbClient, err := r.queries.GetClient(ctx, clientID.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}

	return r.toDomain(dbClient)
}

func (r *clientRepository) GetWithSecretHash(ctx context.Context, clientID uuid.UUID) (*domain.Client, string, error) {
	dbClient, err := r.queries.GetClient(ctx, clientID.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", ErrClientNotFound
		}
		return nil, "", err
	}

	client, err := r.toDomain(dbClient)
	if err != nil {
		return nil, "", err
	}

	return client, dbClient.ClientSecretHash.String, nil
}

func (r *clientRepository) List(ctx context.Context) ([]*domain.Client, error) {
	dbClients, err := r.queries.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	clients := make([]*domain.Client, 0, len(dbClients))
	for _, dbClient := range dbClients {
		client, err := r.toDomain(dbClient)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	return clients, nil
}

func (r *clientRepository) Update(ctx context.Context, client *domain.Client) error {
	redirectURIsJSON, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return err
	}

	return r.queries.UpdateClient(ctx, oidc.UpdateClientParams{
		ClientID:     client.ClientID.String(),
		Name:         client.Name,
		ClientType:   string(client.ClientType),
		RedirectUris: redirectURIsJSON,
	})
}

func (r *clientRepository) UpdateSecret(ctx context.Context, clientID uuid.UUID, secretHash string) error {
	return r.queries.UpdateClientSecret(ctx, oidc.UpdateClientSecretParams{
		ClientID: clientID.String(),
		ClientSecretHash: sql.NullString{
			String: secretHash,
			Valid:  secretHash != "",
		},
	})
}

func (r *clientRepository) Delete(ctx context.Context, clientID uuid.UUID) error {
	return r.queries.DeleteClient(ctx, clientID.String())
}

func (r *clientRepository) toDomain(dbClient oidc.Client) (*domain.Client, error) {
	clientID, err := uuid.Parse(dbClient.ClientID)
	if err != nil {
		return nil, err
	}

	var redirectURIs []string
	if err := json.Unmarshal(dbClient.RedirectUris, &redirectURIs); err != nil {
		return nil, err
	}

	return &domain.Client{
		ClientID:     clientID,
		Name:         dbClient.Name,
		ClientType:   domain.ClientType(dbClient.ClientType),
		RedirectURIs: redirectURIs,
		CreatedAt:    dbClient.CreatedAt,
		UpdatedAt:    dbClient.UpdatedAt,
	}, nil
}
