package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
)

func TestIntegration_RegisterClient(t *testing.T) {
	for _, tt := range []struct {
		name       string
		metadata   string
		clientType domain.ClientType
	}{
		{"default", "", domain.ClientTypeConfidential},
		{"basic", `,"token_endpoint_auth_method":"client_secret_basic"`, domain.ClientTypeConfidential},
		{"post", `,"token_endpoint_auth_method":"client_secret_post"`, domain.ClientTypeConfidential},
		{"public", `,"token_endpoint_auth_method":"none"`, domain.ClientTypePublic},
		{"public with whitespace", `,"token_endpoint_auth_method":" none "`, domain.ClientTypePublic},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler, cleanup := setupTestHandler(t)
			defer cleanup()
			e := echo.New()
			gen.RegisterHandlers(e, handler)

			body := `{"client_name":"registered-client","redirect_uris":["https://example.com/callback"]` + tt.metadata + `}`
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth2/register", strings.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var response gen.ClientRegistrationResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.ClientId == uuid.Nil || response.ClientIdIssuedAt <= 0 {
				t.Fatalf("invalid client identity: %+v", response)
			}
			if response.ClientName == nil || *response.ClientName != "registered-client" {
				t.Fatalf("unexpected client name: %v", response.ClientName)
			}
			if !slices.Equal(response.RedirectUris, []string{"https://example.com/callback"}) {
				t.Errorf("redirect URIs = %v", response.RedirectUris)
			}
			if tt.clientType == domain.ClientTypeConfidential {
				if response.ClientSecret == nil || *response.ClientSecret == "" {
					t.Error("confidential client has no secret")
				}
				if response.ClientSecretExpiresAt == nil || *response.ClientSecretExpiresAt != 0 {
					t.Error("confidential client secret must not expire")
				}
			} else if response.ClientSecret != nil || response.ClientSecretExpiresAt != nil {
				t.Error("public client response contains secret metadata")
			}

			stored, err := handler.clientUseCase.Get(t.Context(), response.ClientId)
			if err != nil {
				t.Fatal(err)
			}
			if stored.ClientType != tt.clientType || stored.Name != *response.ClientName || !slices.Equal(stored.RedirectURIs, response.RedirectUris) {
				t.Errorf("stored client does not match registration: %+v", stored)
			}
		})
	}
}

func TestRegisterClientRejectsInvalidRequest(t *testing.T) {
	for _, body := range []string{`{`, `{}`, `{"redirect_uris":[]}`} {
		t.Run(body, func(t *testing.T) {
			e := echo.New()
			gen.RegisterHandlers(e, &Handler{})
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/oauth2/register", strings.NewReader(body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			var response gen.OAuthError
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Error != gen.InvalidRequest {
				t.Errorf("error = %q, want %q", response.Error, gen.InvalidRequest)
			}
		})
	}
}
