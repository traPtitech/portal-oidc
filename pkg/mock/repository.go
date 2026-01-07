package mock

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
)

// Repository implements repository.Repository for testing
type Repository struct {
	Clients map[string]domain.Client
}

func NewRepository() *Repository {
	return &Repository{
		Clients: make(map[string]domain.Client),
	}
}

// ClientRepository methods

func (m *Repository) CreateClient(_ context.Context, params repository.CreateClientParams) (domain.Client, error) {
	client := domain.Client{
		ID:           params.ID,
		SecretHash:   params.SecretHash,
		Name:         params.Name,
		Type:         params.Type,
		RedirectURIs: params.RedirectURIs,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	m.Clients[uuid.UUID(params.ID).String()] = client
	return client, nil
}

func (m *Repository) GetClient(_ context.Context, id domain.ClientID) (domain.Client, error) {
	client, ok := m.Clients[uuid.UUID(id).String()]
	if !ok {
		return domain.Client{}, sql.ErrNoRows
	}
	return client, nil
}

func (m *Repository) ListClients(_ context.Context) ([]domain.Client, error) {
	var clients []domain.Client
	for _, c := range m.Clients {
		clients = append(clients, c)
	}
	return clients, nil
}

func (m *Repository) UpdateClient(_ context.Context, id domain.ClientID, params repository.UpdateClientParams) (domain.Client, error) {
	client, ok := m.Clients[uuid.UUID(id).String()]
	if !ok {
		return domain.Client{}, sql.ErrNoRows
	}
	client.Name = params.Name
	client.Type = params.Type
	client.RedirectURIs = params.RedirectURIs
	client.UpdatedAt = time.Now()
	m.Clients[uuid.UUID(id).String()] = client
	return client, nil
}

func (m *Repository) UpdateClientSecret(_ context.Context, id domain.ClientID, secretHash *string) (domain.Client, error) {
	client, ok := m.Clients[uuid.UUID(id).String()]
	if !ok {
		return domain.Client{}, sql.ErrNoRows
	}
	client.SecretHash = secretHash
	client.UpdatedAt = time.Now()
	m.Clients[uuid.UUID(id).String()] = client
	return client, nil
}

func (m *Repository) DeleteClient(_ context.Context, id domain.ClientID) error {
	delete(m.Clients, uuid.UUID(id).String())
	return nil
}
