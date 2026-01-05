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
	Sessions      map[string]domain.Session
	UserConsents  map[string]domain.UserConsent
	LoginSessions map[string]domain.LoginSession
	Clients       map[string]domain.Client
}

func NewRepository() *Repository {
	return &Repository{
		Sessions:      make(map[string]domain.Session),
		UserConsents:  make(map[string]domain.UserConsent),
		LoginSessions: make(map[string]domain.LoginSession),
		Clients:       make(map[string]domain.Client),
	}
}

// SessionRepository methods

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

func (m *Repository) UpdateSessionLastActive(_ context.Context, id domain.SessionID, lastActiveAt time.Time) error {
	if sess, ok := m.Sessions[uuid.UUID(id).String()]; ok {
		sess.LastActiveAt = lastActiveAt
		m.Sessions[uuid.UUID(id).String()] = sess
	}
	return nil
}

func (m *Repository) RevokeSession(_ context.Context, id domain.SessionID) error {
	delete(m.Sessions, uuid.UUID(id).String())
	return nil
}

func (m *Repository) ListSessionsByUser(_ context.Context, userID domain.TrapID) ([]domain.Session, error) {
	var sessions []domain.Session
	for _, s := range m.Sessions {
		if s.UserID == userID {
			sessions = append(sessions, s)
		}
	}
	return sessions, nil
}

// UserConsent methods

func (m *Repository) CreateUserConsent(_ context.Context, consent domain.UserConsent) error {
	key := consent.UserID.String() + ":" + uuid.UUID(consent.ClientID).String()
	m.UserConsents[key] = consent
	return nil
}

func (m *Repository) GetUserConsent(_ context.Context, userID domain.TrapID, clientID domain.ClientID) (domain.UserConsent, error) {
	key := userID.String() + ":" + uuid.UUID(clientID).String()
	consent, ok := m.UserConsents[key]
	if !ok {
		return domain.UserConsent{}, sql.ErrNoRows
	}
	return consent, nil
}

func (m *Repository) UpdateUserConsentScopes(_ context.Context, userID domain.TrapID, clientID domain.ClientID, scopes []string, grantedAt time.Time) error {
	key := userID.String() + ":" + uuid.UUID(clientID).String()
	if consent, ok := m.UserConsents[key]; ok {
		consent.Scopes = scopes
		consent.GrantedAt = grantedAt
		m.UserConsents[key] = consent
	}
	return nil
}

func (m *Repository) RevokeUserConsent(_ context.Context, userID domain.TrapID, clientID domain.ClientID) error {
	key := userID.String() + ":" + uuid.UUID(clientID).String()
	delete(m.UserConsents, key)
	return nil
}

// LoginSession methods

func (m *Repository) CreateLoginSession(_ context.Context, sess domain.LoginSession) error {
	m.LoginSessions[uuid.UUID(sess.ID).String()] = sess
	return nil
}

func (m *Repository) GetLoginSession(_ context.Context, id domain.LoginSessionID) (domain.LoginSession, error) {
	sess, ok := m.LoginSessions[uuid.UUID(id).String()]
	if !ok {
		return domain.LoginSession{}, sql.ErrNoRows
	}
	return sess, nil
}

func (m *Repository) DeleteLoginSession(_ context.Context, id domain.LoginSessionID) error {
	delete(m.LoginSessions, uuid.UUID(id).String())
	return nil
}

// OIDCClientRepository methods

func (m *Repository) CreateOIDCClient(_ context.Context, params repository.CreateClientParams) (domain.Client, error) {
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

func (m *Repository) GetOIDCClient(_ context.Context, id domain.ClientID) (domain.Client, error) {
	client, ok := m.Clients[uuid.UUID(id).String()]
	if !ok {
		return domain.Client{}, sql.ErrNoRows
	}
	return client, nil
}

func (m *Repository) ListOIDCClients(_ context.Context) ([]domain.Client, error) {
	var clients []domain.Client
	for _, c := range m.Clients {
		clients = append(clients, c)
	}
	return clients, nil
}

func (m *Repository) UpdateOIDCClient(_ context.Context, id domain.ClientID, params repository.UpdateClientParams) (domain.Client, error) {
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

func (m *Repository) UpdateOIDCClientSecret(_ context.Context, id domain.ClientID, secretHash *string) (domain.Client, error) {
	client, ok := m.Clients[uuid.UUID(id).String()]
	if !ok {
		return domain.Client{}, sql.ErrNoRows
	}
	client.SecretHash = secretHash
	client.UpdatedAt = time.Now()
	m.Clients[uuid.UUID(id).String()] = client
	return client, nil
}

func (m *Repository) DeleteOIDCClient(_ context.Context, id domain.ClientID) error {
	delete(m.Clients, uuid.UUID(id).String())
	return nil
}
