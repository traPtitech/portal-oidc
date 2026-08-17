package v1

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/labstack/echo/v5"
	fositejwt "github.com/ory/fosite/token/jwt"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
)

func TestValidateIDTokenHint(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	otherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate other signing key: %v", err)
	}
	signer := newTestIDTokenSigner(privateKey)

	const (
		issuer  = "https://oidc.example.com"
		userID  = "00000000-0000-0000-0000-000000000001"
		clientA = "00000000-0000-0000-0000-00000000000a"
		clientB = "00000000-0000-0000-0000-00000000000b"
	)
	now := time.Now().UTC().Truncate(time.Second)
	authTime := now.Add(-5 * time.Minute)
	currentSession := &authInfo{UserID: userID, AuthTime: authTime}

	baseClaims := map[string]any{
		"iss":       issuer,
		"sub":       userID,
		"aud":       clientA,
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Add(-4 * time.Minute).Unix(),
		"auth_time": authTime.Unix(),
	}

	tests := []struct {
		name           string
		mutateClaims   func(map[string]any)
		clientID       string
		currentSession *authInfo
		signingKey     *rsa.PrivateKey
		wantErr        bool
	}{
		{
			name:           "valid current session",
			clientID:       clientA,
			currentSession: currentSession,
		},
		{
			name: "valid multiple audiences containing explicit client",
			mutateClaims: func(claims map[string]any) {
				claims["aud"] = []string{"https://api.example.com", clientA}
			},
			clientID:       clientA,
			currentSession: currentSession,
		},
		{
			name: "expired token for current session",
			mutateClaims: func(claims map[string]any) {
				claims["exp"] = now.Add(-time.Minute).Unix()
			},
			clientID:       clientA,
			currentSession: currentSession,
		},
		{
			name: "wrong issuer",
			mutateClaims: func(claims map[string]any) {
				claims["iss"] = "https://attacker.example.com"
			},
			clientID:       clientA,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name: "missing issuer",
			mutateClaims: func(claims map[string]any) {
				delete(claims, "iss")
			},
			clientID:       clientA,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name: "missing subject",
			mutateClaims: func(claims map[string]any) {
				delete(claims, "sub")
			},
			clientID:       clientA,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name: "different logged-in user",
			mutateClaims: func(claims map[string]any) {
				claims["sub"] = "00000000-0000-0000-0000-000000000002"
			},
			clientID:       clientA,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name: "missing audience",
			mutateClaims: func(claims map[string]any) {
				delete(claims, "aud")
			},
			clientID:       clientA,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name:           "explicit client does not match audience",
			clientID:       clientB,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name: "different authentication time",
			mutateClaims: func(claims map[string]any) {
				claims["auth_time"] = authTime.Add(-time.Second).Unix()
			},
			clientID:       clientA,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name: "missing authentication time for current session",
			mutateClaims: func(claims map[string]any) {
				delete(claims, "auth_time")
			},
			clientID:       clientA,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name: "missing expiration",
			mutateClaims: func(claims map[string]any) {
				delete(claims, "exp")
			},
			clientID:       clientA,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name: "missing issued at",
			mutateClaims: func(claims map[string]any) {
				delete(claims, "iat")
			},
			clientID:       clientA,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name: "future issued at",
			mutateClaims: func(claims map[string]any) {
				claims["iat"] = now.Add(time.Minute).Unix()
			},
			clientID:       clientA,
			currentSession: currentSession,
			wantErr:        true,
		},
		{
			name: "expired token without current session",
			mutateClaims: func(claims map[string]any) {
				claims["exp"] = now.Add(-time.Minute).Unix()
			},
			clientID: clientA,
			wantErr:  true,
		},
		{
			name:       "valid token without current session",
			clientID:   clientA,
			signingKey: privateKey,
		},
		{
			name:           "invalid signature",
			clientID:       clientA,
			currentSession: currentSession,
			signingKey:     otherPrivateKey,
			wantErr:        true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := cloneClaims(baseClaims)
			if test.mutateClaims != nil {
				test.mutateClaims(claims)
			}
			signingKey := test.signingKey
			if signingKey == nil {
				signingKey = privateKey
			}

			rawToken := signIDTokenHint(t, signingKey, claims)
			_, err := validateIDTokenHint(
				context.Background(),
				rawToken,
				signer,
				issuer,
				test.clientID,
				test.currentSession,
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateIDTokenHint() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestHasRegisteredAudience(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	client, err := handler.clientUseCase.Create(
		context.Background(),
		"logout-client",
		domain.ClientTypeConfidential,
		[]string{"https://client.example.com/callback"},
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	registered, err := handler.hasRegisteredAudience(context.Background(), []string{
		"https://api.example.com",
		client.ClientID.String(),
	})
	if err != nil {
		t.Fatalf("hasRegisteredAudience() error = %v", err)
	}
	if !registered {
		t.Fatal("hasRegisteredAudience() = false, want true")
	}

	registered, err = handler.hasRegisteredAudience(context.Background(), []string{
		"not-a-client-id",
		"00000000-0000-0000-0000-000000000099",
	})
	if err != nil {
		t.Fatalf("hasRegisteredAudience() error = %v", err)
	}
	if registered {
		t.Fatal("hasRegisteredAudience() = true, want false")
	}
}

func TestGetRPInitiatedLogoutValidatesExplicitClientID(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	const (
		issuer  = "https://oidc.example.com"
		clientA = "00000000-0000-0000-0000-00000000000a"
		clientB = "00000000-0000-0000-0000-00000000000b"
	)
	now := time.Now().UTC().Truncate(time.Second)
	rawToken := signIDTokenHint(t, privateKey, map[string]any{
		"iss":       issuer,
		"sub":       "00000000-0000-0000-0000-000000000001",
		"aud":       clientA,
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Add(-time.Minute).Unix(),
	})

	handler := NewHandler(nil, nil, nil, nil, OAuthConfig{
		Issuer:        issuer,
		SessionSecret: []byte("test-session-secret-32-characters"), //nolint:gosec
		PrivateKey:    privateKey,
		IDTokenSigner: newTestIDTokenSigner(privateKey),
	})
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	query := url.Values{
		"id_token_hint": {rawToken},
		"client_id":     {clientB},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth2/logout?"+query.Encode(), nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestGetRPInitiatedLogoutRejectsHintForDifferentLoggedInUser(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	const (
		issuer       = "https://oidc.example.com"
		loggedInUser = "00000000-0000-0000-0000-000000000001"
		tokenSubject = "00000000-0000-0000-0000-000000000002"
		clientID     = "00000000-0000-0000-0000-00000000000a"
	)
	now := time.Now().UTC().Truncate(time.Second)
	authTime := now.Add(-time.Minute)
	rawToken := signIDTokenHint(t, privateKey, map[string]any{
		"iss":       issuer,
		"sub":       tokenSubject,
		"aud":       clientID,
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"auth_time": authTime.Unix(),
	})

	handler := NewHandler(nil, nil, nil, nil, OAuthConfig{
		Issuer:        issuer,
		SessionSecret: []byte("test-session-secret-32-characters"), //nolint:gosec
		PrivateKey:    privateKey,
		IDTokenSigner: newTestIDTokenSigner(privateKey),
	})
	e := echo.New()
	gen.RegisterHandlers(e, handler)
	sessionCookie := createAuthenticatedSessionCookie(t, handler, loggedInUser, authTime)

	query := url.Values{"id_token_hint": {rawToken}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth2/logout?"+query.Encode(), nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if setCookies := rec.Header().Values("Set-Cookie"); len(setCookies) != 0 {
		t.Fatalf("session was modified before rejecting id_token_hint: %v", setCookies)
	}
}

func TestGetRPInitiatedLogoutFailsClosedWithoutSigningKey(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}

	handler := NewHandler(nil, nil, nil, nil, OAuthConfig{
		Issuer:        "https://oidc.example.com",
		SessionSecret: []byte("test-session-secret-32-characters"), //nolint:gosec
		PrivateKey:    privateKey,
	})
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth2/logout?id_token_hint=token", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

func signIDTokenHint(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	rawToken, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to sign id_token_hint: %v", err)
	}
	return rawToken
}

func cloneClaims(claims map[string]any) map[string]any {
	clone := make(map[string]any, len(claims))
	for key, value := range claims {
		clone[key] = value
	}
	return clone
}

func createAuthenticatedSessionCookie(
	t *testing.T,
	handler *Handler,
	userID string,
	authTime time.Time,
) *http.Cookie {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	session, err := handler.sessions.Get(req, sessionName)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	session.Values["authenticated"] = true
	session.Values["user_id"] = userID
	session.Values["auth_time"] = authTime.Unix()
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("failed to save session: %v", err)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("session cookie count = %d, want 1", len(cookies))
	}
	return cookies[0]
}

func newTestIDTokenSigner(privateKey *rsa.PrivateKey) fositejwt.Signer {
	return &fositejwt.DefaultSigner{
		GetPrivateKey: func(context.Context) (interface{}, error) {
			return privateKey, nil
		},
	}
}
