package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/mock"
	models "github.com/traPtitech/portal-oidc/internal/interface/handler/v1/gen"
)

func newTestConfig(repo *mock.Repository, portal *mock.Portal) Config {
	return Config{
		Host:       "http://localhost:8080",
		Repository: repo,
		PortalImpl: portal,
	}
}

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
	repo := mock.NewRepository()
	server := NewServer(newTestConfig(repo, mock.NewPortal()))

	req := newRequest(t, http.MethodPost, "/v1/clients", models.CreateClientRequest{
		Name:         "test-app",
		Type:         models.CreateClientRequestTypePublic,
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

	if resp.Name != "test-app" {
		t.Errorf("expected name 'test-app', got %v", resp.Name)
	}
	if resp.Type != models.ClientTypePublic {
		t.Errorf("expected type 'public', got %v", resp.Type)
	}
}

func TestListClients(t *testing.T) {
	repo := mock.NewRepository()
	testClientID := uuid.New()
	repo.Clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		Type:         domain.ClientTypePublic,
		Name:         "existing-app",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(newTestConfig(repo, mock.NewPortal()))

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
	if resp[0].Name != "existing-app" {
		t.Errorf("expected name 'existing-app', got %v", resp[0].Name)
	}
}

func TestUpdateClient(t *testing.T) {
	repo := mock.NewRepository()
	testClientID := uuid.New()
	repo.Clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		Type:         domain.ClientTypePublic,
		Name:         "original-name",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(newTestConfig(repo, mock.NewPortal()))

	req := newRequest(t, http.MethodPut, "/v1/clients/"+testClientID.String(), models.UpdateClientRequest{
		Name:         "updated-name",
		Type:         models.Confidential,
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

	if resp.Name != "updated-name" {
		t.Errorf("expected name 'updated-name', got %v", resp.Name)
	}
}

func TestDeleteClient(t *testing.T) {
	repo := mock.NewRepository()
	testClientID := uuid.New()
	repo.Clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		Type:         domain.ClientTypePublic,
		Name:         "to-be-deleted",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(newTestConfig(repo, mock.NewPortal()))

	req := newRequest(t, http.MethodDelete, "/v1/clients/"+testClientID.String(), nil, "testuser")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNoContent, rec.Code, rec.Body.String())
	}

	if _, exists := repo.Clients[testClientID.String()]; exists {
		t.Error("expected client to be deleted from repository")
	}
}

func TestCreateClientUnauthorized(t *testing.T) {
	repo := mock.NewRepository()
	server := NewServer(newTestConfig(repo, mock.NewPortal()))

	req := newRequest(t, http.MethodPost, "/v1/clients", models.CreateClientRequest{
		Name:         "test-app",
		Type:         models.CreateClientRequestTypePublic,
		RedirectUris: []string{"http://localhost:3000/callback"},
	}, "") // No user

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}
