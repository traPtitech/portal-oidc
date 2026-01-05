package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite/storage"

	"github.com/traPtitech/portal-oidc/pkg/domain"
	models "github.com/traPtitech/portal-oidc/pkg/interface/handler/v1/gen"
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

// Helper to create authenticated request with JSON body
func newRequest(t *testing.T, method, path string, body any, userID domain.TrapID) *http.Request {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal body: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if userID != "" {
		req = req.WithContext(context.WithValue(req.Context(), domain.ContextKeyUser, userID))
	}
	return req
}

func TestCreateClient(t *testing.T) {
	repo := newMockRepository()
	server := NewServer(newTestConfig(repo, &mockPortal{}, storage.NewMemoryStore()))

	req := newRequest(t, http.MethodPost, "/v1/clients", models.CreateClientRequest{
		ClientName:   "test-app",
		ClientType:   "public",
		Description:  "Test application",
		RedirectUris: []string{"http://localhost:3000/callback"},
	}, "testuser")

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, rec.Code, rec.Body.String())
	}

	var resp models.Client
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.ClientName != "test-app" {
		t.Errorf("expected client_name 'test-app', got %v", resp.ClientName)
	}
	if resp.ClientType != "public" {
		t.Errorf("expected client_type 'public', got %v", resp.ClientType)
	}
}

func TestListClients(t *testing.T) {
	repo := newMockRepository()
	testClientID := uuid.New()
	repo.clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		UserID:       "testuser",
		Type:         domain.ClientTypePublic,
		Name:         "existing-app",
		Description:  "Existing application",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(newTestConfig(repo, &mockPortal{}, storage.NewMemoryStore()))

	req := newRequest(t, http.MethodGet, "/v1/clients", nil, "testuser")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp []models.Client
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(resp) != 1 {
		t.Fatalf("expected 1 client, got %d", len(resp))
	}
	if resp[0].ClientName != "existing-app" {
		t.Errorf("expected client_name 'existing-app', got %v", resp[0].ClientName)
	}
}

func TestUpdateClient(t *testing.T) {
	repo := newMockRepository()
	testClientID := uuid.New()
	repo.clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		UserID:       "testuser",
		Type:         domain.ClientTypePublic,
		Name:         "original-name",
		Description:  "Original description",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(newTestConfig(repo, &mockPortal{}, storage.NewMemoryStore()))

	req := newRequest(t, http.MethodPut, "/v1/clients/"+testClientID.String(), models.UpdateClientRequest{
		ClientName:   "updated-name",
		ClientType:   "confidential",
		Description:  "Updated description",
		RedirectUris: []string{"http://localhost:4000/callback"},
	}, "testuser")

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp models.Client
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.ClientName != "updated-name" {
		t.Errorf("expected client_name 'updated-name', got %v", resp.ClientName)
	}
}

func TestDeleteClient(t *testing.T) {
	repo := newMockRepository()
	testClientID := uuid.New()
	repo.clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		UserID:       "testuser",
		Type:         domain.ClientTypePublic,
		Name:         "to-be-deleted",
		Description:  "Will be deleted",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(newTestConfig(repo, &mockPortal{}, storage.NewMemoryStore()))

	req := newRequest(t, http.MethodDelete, "/v1/clients/"+testClientID.String(), nil, "testuser")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNoContent, rec.Code, rec.Body.String())
	}

	if _, exists := repo.clients[testClientID.String()]; exists {
		t.Error("expected client to be deleted from repository")
	}
}

func TestCreateClientUnauthorized(t *testing.T) {
	repo := newMockRepository()
	server := NewServer(newTestConfig(repo, &mockPortal{}, storage.NewMemoryStore()))

	req := newRequest(t, http.MethodPost, "/v1/clients", models.CreateClientRequest{
		ClientName:   "test-app",
		ClientType:   "public",
		Description:  "Test application",
		RedirectUris: []string{"http://localhost:3000/callback"},
	}, "") // No user

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}
