package v1

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"

	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
	"github.com/traPtitech/portal-oidc/internal/testutil"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

const (
	testDBName = "oidc_test"
)

var testDB *sql.DB

func TestMain(m *testing.M) {
	k := koanf.New(".")
	ctx := context.Background()

	_ = k.Load(confmap.Provider(map[string]any{
		"mariadb.username": "root",
		"mariadb.password": "password",
		"mariadb.hostname": "127.0.0.1",
		"mariadb.port":     "3307",
	}, "."), nil)

	_ = k.Load(env.Provider("MARIADB_", ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, "MARIADB_"))
	}), nil)

	user := k.String("mariadb.username")
	pass := k.String("mariadb.password")
	host := k.String("mariadb.hostname")
	port := k.String("mariadb.port")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/?parseTime=true", user, pass, host, port)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("failed to connect to database: %v\n", err)
		os.Exit(1)
	}

	if err := db.PingContext(ctx); err != nil {
		fmt.Printf("failed to ping database: %v\n", err)
		os.Exit(1)
	}

	_, err = db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", testDBName))
	if err != nil {
		fmt.Printf("failed to create test database: %v\n", err)
		os.Exit(1)
	}
	_ = db.Close()

	dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&multiStatements=true", user, pass, host, port, testDBName)
	testDB, err = sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("failed to connect to test database: %v\n", err)
		os.Exit(1)
	}

	root, err := testutil.FindProjectRoot()
	if err != nil {
		fmt.Printf("failed to find project root: %v\n", err)
		os.Exit(1)
	}
	schemaPath := filepath.Join(root, "db", "schema.sql")
	schemaSQL, err := os.ReadFile(schemaPath) //nolint:gosec
	if err != nil {
		fmt.Printf("failed to read schema file: %v\n", err)
		os.Exit(1)
	}

	_, err = testDB.ExecContext(ctx, string(schemaSQL))
	if err != nil {
		fmt.Printf("failed to create schema: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	_ = testDB.Close()

	os.Exit(code)
}

func setupTestHandler(t *testing.T) (*Handler, func()) {
	t.Helper()

	ctx := context.Background()

	queries, err := oidc.Prepare(ctx, testDB)
	if err != nil {
		t.Fatalf("failed to prepare queries: %v", err)
	}

	if err := queries.DeleteAllClients(ctx); err != nil {
		t.Fatalf("failed to clean up clients table: %v", err)
	}

	clientRepo := repository.NewClientRepository(queries)
	clientUseCase := usecase.NewClientUseCase(clientRepo)

	oauthStorage := repository.NewOAuthStorage(queries)
	fositeConfig := &fosite.Config{
		AccessTokenLifespan:            time.Hour,
		RefreshTokenLifespan:           30 * 24 * time.Hour,
		AuthorizeCodeLifespan:          5 * time.Minute,
		IDTokenLifespan:                time.Hour,
		GlobalSecret:                   []byte("test-secret-key-32-characters!!"),
		ScopeStrategy:                  fosite.ExactScopeStrategy,
		AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
		SendDebugMessagesToClients:     false,
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: true,
		AccessTokenIssuer:              "http://localhost:8080",
		IDTokenIssuer:                  "http://localhost:8080",
	}
	oauth2Provider := compose.Compose(
		fositeConfig,
		oauthStorage,
		compose.NewOAuth2HMACStrategy(fositeConfig),
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
	)

	handler := NewHandler(clientUseCase, oauth2Provider, nil, OAuthConfig{
		Issuer:      "http://localhost:8080",
		Environment: "development",
		TestUserID:  "testuser",
	})

	cleanup := func() {
		_ = queries.DeleteAllClients(ctx)
		_ = queries.Close()
	}

	return handler, cleanup
}

func TestIntegration_CreateClient(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	e := echo.New()
	gen.RegisterHandlers(e, handler)

	reqBody := `{"name":"integration-test-client","client_type":"confidential","redirect_uris":["http://localhost:3000/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d, body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp gen.ClientWithSecret
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Name != "integration-test-client" {
		t.Errorf("Name = %q, want %q", resp.Name, "integration-test-client")
	}
	if resp.ClientType != gen.Confidential {
		t.Errorf("ClientType = %q, want %q", resp.ClientType, gen.Confidential)
	}
	if resp.ClientSecret == "" {
		t.Error("ClientSecret should not be empty")
	}
	if len(resp.RedirectUris) != 1 {
		t.Errorf("len(RedirectUris) = %d, want 1", len(resp.RedirectUris))
	}
}

func TestIntegration_GetClients(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	e := echo.New()
	gen.RegisterHandlers(e, handler)

	reqBody := `{"name":"test-client","client_type":"confidential","redirect_uris":["http://localhost:3000/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var clients []gen.Client
	if err := json.Unmarshal(rec.Body.Bytes(), &clients); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(clients) != 1 {
		t.Errorf("len(clients) = %d, want 1", len(clients))
	}
}

func TestIntegration_GetClient(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	e := echo.New()
	gen.RegisterHandlers(e, handler)

	reqBody := `{"name":"test-client","client_type":"confidential","redirect_uris":["http://localhost:3000/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var created gen.ClientWithSecret
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients/"+created.ClientId.String(), nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var client gen.Client
	if err := json.Unmarshal(rec.Body.Bytes(), &client); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if client.ClientId != created.ClientId {
		t.Errorf("ClientId = %s, want %s", client.ClientId, created.ClientId)
	}
	if client.Name != "test-client" {
		t.Errorf("Name = %q, want %q", client.Name, "test-client")
	}
}

func TestIntegration_GetClient_NotFound(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	e := echo.New()
	gen.RegisterHandlers(e, handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients/00000000-0000-0000-0000-000000000000", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestIntegration_UpdateClient(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	e := echo.New()
	gen.RegisterHandlers(e, handler)

	reqBody := `{"name":"original","client_type":"confidential","redirect_uris":["http://localhost:3000/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var created gen.ClientWithSecret
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	updateBody := `{"name":"updated","client_type":"public","redirect_uris":["http://localhost:4000/callback"]}`
	req = httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/"+created.ClientId.String(), strings.NewReader(updateBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var updated gen.Client
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if updated.Name != "updated" {
		t.Errorf("Name = %q, want %q", updated.Name, "updated")
	}
	if updated.ClientType != gen.Public {
		t.Errorf("ClientType = %q, want %q", updated.ClientType, gen.Public)
	}
	if updated.RedirectUris[0] != "http://localhost:4000/callback" {
		t.Errorf("RedirectUris[0] = %q, want %q", updated.RedirectUris[0], "http://localhost:4000/callback")
	}
}

func TestIntegration_DeleteClient(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	e := echo.New()
	gen.RegisterHandlers(e, handler)

	reqBody := `{"name":"to-delete","client_type":"confidential","redirect_uris":["http://localhost:3000/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var created gen.ClientWithSecret
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/admin/clients/"+created.ClientId.String(), nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients/"+created.ClientId.String(), nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestIntegration_RegenerateClientSecret(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	e := echo.New()
	gen.RegisterHandlers(e, handler)

	reqBody := `{"name":"test-client","client_type":"confidential","redirect_uris":["http://localhost:3000/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients", strings.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var created gen.ClientWithSecret
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients/"+created.ClientId.String()+"/secret", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var secret gen.ClientSecret
	if err := json.Unmarshal(rec.Body.Bytes(), &secret); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if secret.ClientSecret == "" {
		t.Error("ClientSecret should not be empty")
	}
	if secret.ClientSecret == created.ClientSecret {
		t.Error("new secret should be different from original")
	}
}

func TestIntegration_FullWorkflow(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	e := echo.New()
	gen.RegisterHandlers(e, handler)

	// 1. Create client
	createBody := `{"name":"workflow-test","client_type":"confidential","redirect_uris":["http://localhost:3000/callback"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients", strings.NewReader(createBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Create: status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var created gen.ClientWithSecret
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// 2. Verify in list
	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var clients []gen.Client
	if err := json.Unmarshal(rec.Body.Bytes(), &clients); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(clients) != 1 {
		t.Errorf("List: len = %d, want 1", len(clients))
	}

	// 3. Update client
	updateBody := `{"name":"workflow-updated","client_type":"public","redirect_uris":["http://localhost:4000/callback"]}`
	req = httptest.NewRequest(http.MethodPut, "/api/v1/admin/clients/"+created.ClientId.String(), strings.NewReader(updateBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Update: status = %d, want %d", rec.Code, http.StatusOK)
	}

	// 4. Regenerate secret
	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients/"+created.ClientId.String()+"/secret", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("RegenerateSecret: status = %d, want %d", rec.Code, http.StatusOK)
	}

	// 5. Delete client
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/admin/clients/"+created.ClientId.String(), nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Delete: status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// 6. Verify list is empty
	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if err := json.Unmarshal(rec.Body.Bytes(), &clients); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(clients) != 0 {
		t.Errorf("Final List: len = %d, want 0", len(clients))
	}
}
