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
	Sessions              map[string]domain.Session
	AuthorizationRequests map[string]domain.AuthorizationRequest
	AuthorizationCodes    map[string]domain.AuthorizationCode
	Clients               map[string]domain.Client
}

func NewRepository() *Repository {
	return &Repository{
		Sessions:              make(map[string]domain.Session),
		AuthorizationRequests: make(map[string]domain.AuthorizationRequest),
		AuthorizationCodes:    make(map[string]domain.AuthorizationCode),
		Clients:               make(map[string]domain.Client),
	}
}

// Session methods

func (m *Repository) CreateSession(_ context.Context, sess domain.Session) error {
	m.Sessions[uuid.UUID(sess.ID).String()] = sess
	return nil
}

func (m *Repository) GetSession(_ context.Context, id domain.SessionID) (domain.Session, error) {
	sess, ok := m.Sessions[uuid.UUID(id).String()]
	if !ok {
		return domain.Session{}, sql.ErrNoRows
	}
	return sess, nil
}

func (m *Repository) DeleteSession(_ context.Context, id domain.SessionID) error {
	delete(m.Sessions, uuid.UUID(id).String())
	return nil
}

// AuthorizationRequest methods

func (m *Repository) CreateAuthorizationRequest(_ context.Context, req domain.AuthorizationRequest) error {
	m.AuthorizationRequests[uuid.UUID(req.ID).String()] = req
	return nil
}

func (m *Repository) GetAuthorizationRequest(_ context.Context, id domain.AuthorizationRequestID) (domain.AuthorizationRequest, error) {
	req, ok := m.AuthorizationRequests[uuid.UUID(id).String()]
	if !ok {
		return domain.AuthorizationRequest{}, sql.ErrNoRows
	}
	return req, nil
}

func (m *Repository) UpdateAuthorizationRequestUserID(_ context.Context, id domain.AuthorizationRequestID, userID domain.TrapID) error {
	req, ok := m.AuthorizationRequests[uuid.UUID(id).String()]
	if !ok {
		return sql.ErrNoRows
	}
	req.UserID = &userID
	m.AuthorizationRequests[uuid.UUID(id).String()] = req
	return nil
}

func (m *Repository) DeleteAuthorizationRequest(_ context.Context, id domain.AuthorizationRequestID) error {
	delete(m.AuthorizationRequests, uuid.UUID(id).String())
	return nil
}

// AuthorizationCode methods

func (m *Repository) CreateAuthorizationCode(_ context.Context, code domain.AuthorizationCode) error {
	m.AuthorizationCodes[code.Code] = code
	return nil
}

func (m *Repository) GetAuthorizationCode(_ context.Context, code string) (domain.AuthorizationCode, error) {
	c, ok := m.AuthorizationCodes[code]
	if !ok {
		return domain.AuthorizationCode{}, sql.ErrNoRows
	}
	return c, nil
}

func (m *Repository) MarkAuthorizationCodeUsed(_ context.Context, code string) error {
	c, ok := m.AuthorizationCodes[code]
	if !ok {
		return sql.ErrNoRows
	}
	c.Used = true
	m.AuthorizationCodes[code] = c
	return nil
}

func (m *Repository) DeleteAuthorizationCode(_ context.Context, code string) error {
	delete(m.AuthorizationCodes, code)
	return nil
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
