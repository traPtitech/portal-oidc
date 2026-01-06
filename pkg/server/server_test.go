package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/infrastructure/mock"
	models "github.com/traPtitech/portal-oidc/pkg/interface/handler/v1/gen"
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

// OAuth2 Authorization Endpoint Tests

func TestAuthEndpoint_NoSession_RedirectsToLogin(t *testing.T) {
	repo := mock.NewRepository()
	testClientID := uuid.New()
	repo.Clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		Type:         domain.ClientTypePublic,
		Name:         "test-app",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(newTestConfig(repo, mock.NewPortal()))

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+url.Values{
		"client_id":             {testClientID.String()},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"test-state-12345"},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound && rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect status, got %d: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if location != "/login" {
		t.Errorf("expected redirect to /login, got %s", location)
	}

	// Should set auth_request cookie
	cookies := rec.Result().Cookies()
	var authRequestCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "auth_request" {
			authRequestCookie = c
			break
		}
	}
	if authRequestCookie == nil {
		t.Error("expected auth_request cookie to be set")
	}
}

func TestAuthEndpoint_WithSession_ReturnsCode(t *testing.T) {
	repo := mock.NewRepository()
	testClientID := uuid.New()
	repo.Clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		Type:         domain.ClientTypePublic,
		Name:         "test-app",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	// Create a valid session
	sessionID := uuid.New()
	now := time.Now()
	repo.Sessions[sessionID.String()] = domain.Session{
		ID:           domain.SessionID(sessionID),
		UserID:       "testuser",
		AuthTime:     now,
		LastActiveAt: now,
		ExpiresAt:    now.Add(24 * time.Hour),
		CreatedAt:    now,
	}

	server := NewServer(newTestConfig(repo, mock.NewPortal()))

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+url.Values{
		"client_id":             {testClientID.String()},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"test-state-12345"},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "gate_token", Value: sessionID.String()})

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound && rec.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect status, got %d: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}

	if !strings.HasPrefix(parsedURL.String(), "http://localhost:3000/callback") {
		t.Errorf("expected redirect to callback, got %s", location)
	}

	code := parsedURL.Query().Get("code")
	if code == "" {
		t.Error("expected code in redirect URL")
	}

	state := parsedURL.Query().Get("state")
	if state != "test-state-12345" {
		t.Errorf("expected state 'test-state-12345', got %s", state)
	}
}

func TestAuthEndpoint_InvalidClient_ReturnsError(t *testing.T) {
	repo := mock.NewRepository()
	server := NewServer(newTestConfig(repo, mock.NewPortal()))

	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+url.Values{
		"client_id":     {uuid.New().String()},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}.Encode(), nil)

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnauthorized {
		t.Errorf("expected error status, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Login Endpoint Tests

func TestLoginHandler_MissingCookie_ReturnsBadRequest(t *testing.T) {
	repo := mock.NewRepository()
	portal := mock.NewPortal()
	server := NewServer(newTestConfig(repo, portal))

	form := url.Values{
		"trap_id":  {"testuser"},
		"password": {"password123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestLoginHandler_InvalidCredentials_ReturnsUnauthorized(t *testing.T) {
	repo := mock.NewRepository()
	portal := mock.NewPortal()
	portal.Users["testuser"] = "correct-password"

	testClientID := uuid.New()
	repo.Clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		Type:         domain.ClientTypePublic,
		Name:         "test-app",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	authReqID := uuid.New()
	now := time.Now()
	repo.AuthorizationRequests[authReqID.String()] = domain.AuthorizationRequest{
		ID:                  domain.AuthorizationRequestID(authReqID),
		ClientID:            testClientID.String(),
		RedirectURI:         "http://localhost:3000/callback",
		Scope:               "openid",
		State:               "test-state",
		CodeChallenge:       "test-challenge",
		CodeChallengeMethod: "S256",
		CreatedAt:           now,
		ExpiresAt:           now.Add(15 * time.Minute),
	}

	server := NewServer(newTestConfig(repo, portal))

	form := url.Values{
		"trap_id":  {"testuser"},
		"password": {"wrong-password"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "auth_request", Value: authReqID.String()})

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d: %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestLoginHandler_ValidCredentials_RedirectsToAuthorize(t *testing.T) {
	repo := mock.NewRepository()
	portal := mock.NewPortal()
	portal.Users["testuser"] = "correct-password"

	testClientID := uuid.New()
	repo.Clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		Type:         domain.ClientTypePublic,
		Name:         "test-app",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	authReqID := uuid.New()
	now := time.Now()
	repo.AuthorizationRequests[authReqID.String()] = domain.AuthorizationRequest{
		ID:                  domain.AuthorizationRequestID(authReqID),
		ClientID:            testClientID.String(),
		RedirectURI:         "http://localhost:3000/callback",
		Scope:               "openid",
		State:               "test-state",
		CodeChallenge:       "test-challenge",
		CodeChallengeMethod: "S256",
		CreatedAt:           now,
		ExpiresAt:           now.Add(15 * time.Minute),
	}

	server := NewServer(newTestConfig(repo, portal))

	form := url.Values{
		"trap_id":  {"testuser"},
		"password": {"correct-password"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "auth_request", Value: authReqID.String()})

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect status, got %d: %s", rec.Code, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "/oauth2/authorize") {
		t.Errorf("expected redirect to /oauth2/authorize, got %s", location)
	}

	// Should set gate_token cookie
	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "gate_token" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Error("expected gate_token cookie to be set")
	}

	// Verify session was created
	if len(repo.Sessions) != 1 {
		t.Errorf("expected 1 session to be created, got %d", len(repo.Sessions))
	}

	// Verify authorization request was deleted
	if len(repo.AuthorizationRequests) != 0 {
		t.Errorf("expected authorization request to be deleted, got %d", len(repo.AuthorizationRequests))
	}
}

// Token Endpoint Tests

func TestTokenEndpoint_InvalidCode_ReturnsError(t *testing.T) {
	repo := mock.NewRepository()
	testClientID := uuid.New()
	repo.Clients[testClientID.String()] = domain.Client{
		ID:           domain.ClientID(testClientID),
		Type:         domain.ClientTypePublic,
		Name:         "test-app",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	server := NewServer(newTestConfig(repo, mock.NewPortal()))

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"invalid-code"},
		"redirect_uri": {"http://localhost:3000/callback"},
		"client_id":    {testClientID.String()},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}
