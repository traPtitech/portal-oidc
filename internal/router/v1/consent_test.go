package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
)

func TestIntegration_AuthorizeConsentWithAuthenticatedSession(t *testing.T) {
	for _, tt := range []struct {
		name          string
		environment   string
		authenticated bool
		granted       bool
		prompt        string
		wantPath      string
		wantError     string
	}{
		{name: "login required before consent", environment: "production", wantPath: "/login"},
		{name: "missing consent", environment: "production", authenticated: true, wantPath: "/oauth2/consent"},
		{name: "silent request needs consent", environment: "production", authenticated: true, prompt: "none", wantError: "consent_required"},
		{name: "granted consent", environment: "production", authenticated: true, granted: true},
		{name: "development preserves session user", environment: "development", authenticated: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler, cleanup := setupTestHandler(t)
			defer cleanup()
			handler.config.Environment = tt.environment
			handler.sessions = sessions.NewCookieStore([]byte("consent-test-session-secret-32-bytes"))

			ctx := context.Background()
			redirectURI := "https://client.example/callback"
			clientID := createAuthorizeTestClient(t, redirectURI)
			userID := uuid.New()
			if tt.granted {
				if err := handler.consents.Upsert(ctx, domain.UserConsent{
					UserID: userID, ClientID: clientID, Scopes: []string{"openid"},
				}); err != nil {
					t.Fatalf("grant consent: %v", err)
				}
			}

			state := "consent-test-state"
			query := authorizeQuery(clientID, redirectURI, state)
			query.Set("code_challenge", tokenS256Challenge(strings.Repeat("a", 43)))
			query.Set("code_challenge_method", "S256")
			if tt.prompt != "" {
				query.Set("prompt", tt.prompt)
			}
			requestURL := "/oauth2/authorize?" + query.Encode()
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
			if tt.authenticated {
				req.AddCookie(createAuthenticatedSessionCookie(t, handler, userID.String(), time.Now().Add(-time.Minute)))
			}
			rec := httptest.NewRecorder()
			e := echo.New()
			gen.RegisterHandlers(e, handler)
			e.ServeHTTP(rec, req)

			if tt.wantError != "" {
				assertAuthorizeErrorRedirect(t, rec, redirectURI, tt.wantError, state)
				return
			}
			location, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			if tt.wantPath != "" {
				if rec.Code != http.StatusFound || location.Path != tt.wantPath {
					t.Fatalf("status = %d, location = %q, want redirect to %q", rec.Code, location, tt.wantPath)
				}
				if got := location.Query().Get("return_url"); got != requestURL {
					t.Fatalf("return_url = %q, want %q", got, requestURL)
				}
				return
			}

			assertAuthorizeErrorRedirect(t, rec, redirectURI, "", state)
			if location.Query().Get("code") == "" {
				t.Fatal("authorization code is missing")
			}
			var storedUserID uuid.UUID
			if err := testDB.QueryRowContext(ctx, "SELECT user_id FROM authorization_codes WHERE client_id = $1", clientID).Scan(&storedUserID); err != nil {
				t.Fatalf("read authorization code subject: %v", err)
			}
			if storedUserID != userID {
				t.Fatalf("authorization code subject = %s, want authenticated user %s", storedUserID, userID)
			}
		})
	}
}
