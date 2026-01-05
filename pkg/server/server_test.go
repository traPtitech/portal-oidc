package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite/storage"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

// mockPortal implements portal.Portal for testing
type mockPortal struct {
	users map[string]string // trapID -> password
}

func (m *mockPortal) GetGrade(_ context.Context, _ domain.TrapID) (string, error) {
	return "B1", nil
}

func (m *mockPortal) VerifyPassword(_ context.Context, id domain.TrapID, password string) (bool, error) {
	if m.users == nil {
		return true, nil
	}
	expected, ok := m.users[string(id)]
	if !ok {
		return false, nil
	}
	return expected == password, nil
}

// mockRepository implements repository.Repository for testing
type mockRepository struct {
	sessions      map[string]domain.Session
	userConsents  map[string]domain.UserConsent
	loginSessions map[string]domain.LoginSession
	clients       map[string]domain.Client
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		sessions:      make(map[string]domain.Session),
		userConsents:  make(map[string]domain.UserConsent),
		loginSessions: make(map[string]domain.LoginSession),
		clients:       make(map[string]domain.Client),
	}
}

// SessionRepository methods
func (m *mockRepository) CreateSession(_ context.Context, sess domain.Session) error {
	m.sessions[uuid.UUID(sess.ID).String()] = sess
	return nil
}

func (m *mockRepository) GetSession(_ context.Context, id domain.SessionID) (domain.Session, error) {
	sess, ok := m.sessions[uuid.UUID(id).String()]
	if !ok {
		return domain.Session{}, sql.ErrNoRows
	}
	return sess, nil
}

func (m *mockRepository) UpdateSessionLastActive(_ context.Context, id domain.SessionID, lastActiveAt time.Time) error {
	if sess, ok := m.sessions[uuid.UUID(id).String()]; ok {
		sess.LastActiveAt = lastActiveAt
		m.sessions[uuid.UUID(id).String()] = sess
	}
	return nil
}

func (m *mockRepository) RevokeSession(_ context.Context, id domain.SessionID) error {
	delete(m.sessions, uuid.UUID(id).String())
	return nil
}

func (m *mockRepository) ListSessionsByUser(_ context.Context, userID domain.TrapID) ([]domain.Session, error) {
	var sessions []domain.Session
	for _, s := range m.sessions {
		if s.UserID == userID {
			sessions = append(sessions, s)
		}
	}
	return sessions, nil
}

// UserConsent methods
func (m *mockRepository) CreateUserConsent(_ context.Context, consent domain.UserConsent) error {
	key := consent.UserID.String() + ":" + uuid.UUID(consent.ClientID).String()
	m.userConsents[key] = consent
	return nil
}

func (m *mockRepository) GetUserConsent(_ context.Context, userID domain.TrapID, clientID domain.ClientID) (domain.UserConsent, error) {
	key := userID.String() + ":" + uuid.UUID(clientID).String()
	consent, ok := m.userConsents[key]
	if !ok {
		return domain.UserConsent{}, sql.ErrNoRows
	}
	return consent, nil
}

func (m *mockRepository) UpdateUserConsentScopes(_ context.Context, userID domain.TrapID, clientID domain.ClientID, scopes []string, grantedAt time.Time) error {
	key := userID.String() + ":" + uuid.UUID(clientID).String()
	if consent, ok := m.userConsents[key]; ok {
		consent.Scopes = scopes
		consent.GrantedAt = grantedAt
		m.userConsents[key] = consent
	}
	return nil
}

func (m *mockRepository) RevokeUserConsent(_ context.Context, userID domain.TrapID, clientID domain.ClientID) error {
	key := userID.String() + ":" + uuid.UUID(clientID).String()
	delete(m.userConsents, key)
	return nil
}

// LoginSession methods
func (m *mockRepository) CreateLoginSession(_ context.Context, sess domain.LoginSession) error {
	m.loginSessions[uuid.UUID(sess.ID).String()] = sess
	return nil
}

func (m *mockRepository) GetLoginSession(_ context.Context, id domain.LoginSessionID) (domain.LoginSession, error) {
	sess, ok := m.loginSessions[uuid.UUID(id).String()]
	if !ok {
		return domain.LoginSession{}, sql.ErrNoRows
	}
	return sess, nil
}

func (m *mockRepository) DeleteLoginSession(_ context.Context, id domain.LoginSessionID) error {
	delete(m.loginSessions, uuid.UUID(id).String())
	return nil
}

// OIDCClientRepository methods
func (m *mockRepository) CreateOIDCClient(_ context.Context, id uuid.UUID, userID domain.TrapID, typ domain.ClientType, name string, desc string, secret string, redirectURIs []string) (domain.Client, error) {
	client := domain.Client{
		ID:           domain.ClientID(id),
		UserID:       userID,
		Type:         typ,
		Name:         name,
		Description:  desc,
		Secret:       secret,
		RedirectURIs: redirectURIs,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	m.clients[id.String()] = client
	return client, nil
}

func (m *mockRepository) GetOIDCClient(_ context.Context, id domain.ClientID) (domain.Client, error) {
	client, ok := m.clients[uuid.UUID(id).String()]
	if !ok {
		return domain.Client{}, sql.ErrNoRows
	}
	return client, nil
}

func (m *mockRepository) ListOIDCClientsByUser(_ context.Context, userID domain.TrapID) ([]domain.Client, error) {
	var clients []domain.Client
	for _, c := range m.clients {
		if c.UserID == userID {
			clients = append(clients, c)
		}
	}
	return clients, nil
}

func (m *mockRepository) UpdateOIDCClient(_ context.Context, id domain.ClientID, _ domain.TrapID, typ domain.ClientType, name string, desc string, redirectURIs []string) (domain.Client, error) {
	client, ok := m.clients[uuid.UUID(id).String()]
	if !ok {
		return domain.Client{}, sql.ErrNoRows
	}
	client.Type = typ
	client.Name = name
	client.Description = desc
	client.RedirectURIs = redirectURIs
	client.UpdatedAt = time.Now()
	m.clients[uuid.UUID(id).String()] = client
	return client, nil
}

func (m *mockRepository) UpdateOIDCClientSecret(_ context.Context, id domain.ClientID, secret string) (domain.Client, error) {
	client, ok := m.clients[uuid.UUID(id).String()]
	if !ok {
		return domain.Client{}, sql.ErrNoRows
	}
	client.Secret = secret
	client.UpdatedAt = time.Now()
	m.clients[uuid.UUID(id).String()] = client
	return client, nil
}

func (m *mockRepository) DeleteOIDCClient(_ context.Context, id domain.ClientID) error {
	delete(m.clients, uuid.UUID(id).String())
	return nil
}

// Helper to create test Config with mocks
func newTestConfig(repo *mockRepository, portal *mockPortal, store *storage.MemoryStore) Config {
	return Config{
		OIDCSecret:      "k8sSecretValue2024!@#$%^&*()_+Ab", //nolint:gosec // test credentials
		Host:            "http://localhost:8080",
		SessionLifespan: time.Hour,
		Repository:      repo,
		PortalImpl:      portal,
		Store:           store,
	}
}

func TestCreateClient(t *testing.T) {
	repo := newMockRepository()
	portal := &mockPortal{}
	store := storage.NewMemoryStore()
	config := newTestConfig(repo, portal, store)

	server := NewServer(config)

	// Create request with user context
	body := `{"client_name":"test-app","client_type":"public","description":"Test application","redirect_uris":["http://localhost:3000/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), domain.ContextKeyUser, domain.TrapID("testuser")))

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["client_name"] != "test-app" {
		t.Errorf("expected client_name 'test-app', got %v", resp["client_name"])
	}
	if resp["client_type"] != "public" {
		t.Errorf("expected client_type 'public', got %v", resp["client_type"])
	}
}

func TestListClients(t *testing.T) {
	repo := newMockRepository()
	portal := &mockPortal{}
	store := storage.NewMemoryStore()
	config := newTestConfig(repo, portal, store)

	// Pre-populate with a client
	testClientID := uuid.New()
	repo.clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		UserID:       domain.TrapID("testuser"),
		Type:         domain.ClientTypePublic,
		Name:         "existing-app",
		Description:  "Existing application",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(config)

	req := httptest.NewRequest(http.MethodGet, "/v1/clients", nil)
	req = req.WithContext(context.WithValue(req.Context(), domain.ContextKeyUser, domain.TrapID("testuser")))

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(resp) != 1 {
		t.Errorf("expected 1 client, got %d", len(resp))
	}
	if resp[0]["client_name"] != "existing-app" {
		t.Errorf("expected client_name 'existing-app', got %v", resp[0]["client_name"])
	}
}

func TestUpdateClient(t *testing.T) {
	repo := newMockRepository()
	portal := &mockPortal{}
	store := storage.NewMemoryStore()
	config := newTestConfig(repo, portal, store)

	// Pre-populate with a client
	testClientID := uuid.New()
	repo.clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		UserID:       domain.TrapID("testuser"),
		Type:         domain.ClientTypePublic,
		Name:         "original-name",
		Description:  "Original description",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(config)

	body := `{"client_name":"updated-name","client_type":"confidential","description":"Updated description","redirect_uris":["http://localhost:4000/callback"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/clients/"+testClientID.String(), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), domain.ContextKeyUser, domain.TrapID("testuser")))

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["client_name"] != "updated-name" {
		t.Errorf("expected client_name 'updated-name', got %v", resp["client_name"])
	}
}

func TestDeleteClient(t *testing.T) {
	repo := newMockRepository()
	portal := &mockPortal{}
	store := storage.NewMemoryStore()
	config := newTestConfig(repo, portal, store)

	// Pre-populate with a client
	testClientID := uuid.New()
	repo.clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		UserID:       domain.TrapID("testuser"),
		Type:         domain.ClientTypePublic,
		Name:         "to-be-deleted",
		Description:  "Will be deleted",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(config)

	req := httptest.NewRequest(http.MethodDelete, "/v1/clients/"+testClientID.String(), nil)
	req = req.WithContext(context.WithValue(req.Context(), domain.ContextKeyUser, domain.TrapID("testuser")))

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d: %s", http.StatusNoContent, rec.Code, rec.Body.String())
	}

	// Verify client was deleted
	if _, exists := repo.clients[testClientID.String()]; exists {
		t.Error("expected client to be deleted from repository")
	}
}

func TestCreateClientUnauthorized(t *testing.T) {
	repo := newMockRepository()
	portal := &mockPortal{}
	store := storage.NewMemoryStore()
	config := newTestConfig(repo, portal, store)

	server := NewServer(config)

	body := `{"client_name":"test-app","client_type":"public","description":"Test application","redirect_uris":["http://localhost:3000/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No user context set

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}
