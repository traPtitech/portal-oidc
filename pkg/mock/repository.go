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
	Clients       map[string]domain.Client
	Sessions      map[string]domain.Session
	LoginSessions map[string]domain.LoginSession
}

func NewRepository() *Repository {
	return &Repository{
		Clients:       make(map[string]domain.Client),
		Sessions:      make(map[string]domain.Session),
		LoginSessions: make(map[string]domain.LoginSession),
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

// SessionRepository methods

func (m *Repository) CreateSession(_ context.Context, params repository.CreateSessionParams) (domain.Session, error) {
	session := domain.Session{
		ID:            params.ID,
		UserID:        params.UserID,
		ClientID:      params.ClientID,
		AllowedScopes: params.AllowedScopes,
		CreatedAt:     time.Now(),
		ExpiresAt:     params.ExpiresAt,
	}
	m.Sessions[uuid.UUID(params.ID).String()] = session
	return session, nil
}

func (m *Repository) GetSession(_ context.Context, id domain.SessionID) (domain.Session, error) {
	session, ok := m.Sessions[uuid.UUID(id).String()]
	if !ok {
		return domain.Session{}, sql.ErrNoRows
	}
	if session.ExpiresAt.Before(time.Now()) {
		return domain.Session{}, sql.ErrNoRows
	}
	return session, nil
}

func (m *Repository) DeleteSession(_ context.Context, id domain.SessionID) error {
	delete(m.Sessions, uuid.UUID(id).String())
	return nil
}

func (m *Repository) DeleteExpiredSessions(_ context.Context) error {
	now := time.Now()
	for id, session := range m.Sessions {
		if session.ExpiresAt.Before(now) {
			delete(m.Sessions, id)
		}
	}
	return nil
}

func (m *Repository) CreateLoginSession(_ context.Context, params repository.CreateLoginSessionParams) (domain.LoginSession, error) {
	session := domain.LoginSession{
		ID:            params.ID,
		Forms:         params.Forms,
		AllowedScopes: params.AllowedScopes,
		UserID:        params.UserID,
		ClientID:      params.ClientID,
		CreatedAt:     time.Now(),
		ExpiresAt:     params.ExpiresAt,
	}
	m.LoginSessions[uuid.UUID(params.ID).String()] = session
	return session, nil
}

func (m *Repository) GetLoginSession(_ context.Context, id domain.LoginSessionID) (domain.LoginSession, error) {
	session, ok := m.LoginSessions[uuid.UUID(id).String()]
	if !ok {
		return domain.LoginSession{}, sql.ErrNoRows
	}
	if session.ExpiresAt.Before(time.Now()) {
		return domain.LoginSession{}, sql.ErrNoRows
	}
	return session, nil
}

func (m *Repository) DeleteLoginSession(_ context.Context, id domain.LoginSessionID) error {
	delete(m.LoginSessions, uuid.UUID(id).String())
	return nil
}

func (m *Repository) DeleteExpiredLoginSessions(_ context.Context) error {
	now := time.Now()
	for id, session := range m.LoginSessions {
		if session.ExpiresAt.Before(now) {
			delete(m.LoginSessions, id)
		}
	}
	return nil
}
