package v1

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/gorilla/sessions"
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

func TestRPInitiatedLogoutValidatesExplicitClientIDForGETAndPOST(t *testing.T) {
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

	handler := newRPLogoutTestHandler(newTestIDTokenSigner(privateKey))
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	params := url.Values{
		"id_token_hint": {rawToken},
		"client_id":     {clientB},
	}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			target := "/oauth2/logout"
			var body io.Reader
			if method == http.MethodGet {
				target += "?" + params.Encode()
			} else {
				body = strings.NewReader(params.Encode())
			}

			req := httptest.NewRequestWithContext(context.Background(), method, target, body)
			if method == http.MethodPost {
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

func TestRPInitiatedLogoutUntrustedHintRequiresConfirmation(t *testing.T) {
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

	handler := newRPLogoutTestHandler(newTestIDTokenSigner(privateKey))
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	tests := []struct {
		name        string
		idTokenHint string
	}{
		{name: "malformed hint", idTokenHint: "not-a-token"},
		{name: "different logged-in user", idTokenHint: rawToken},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sessionCookie := createAuthenticatedSessionCookie(t, handler, loggedInUser, authTime)
			query := url.Values{"id_token_hint": {test.idTokenHint}}
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"/oauth2/logout?"+query.Encode(),
				nil,
			)
			req.AddCookie(sessionCookie)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			requireLogoutConfirmation(t, handler, rec, loggedInUser)
		})
	}
}

func TestRPInitiatedLogoutWithoutHintRequiresConfirmation(t *testing.T) {
	t.Parallel()

	handler := newRPLogoutTestHandler(nil)
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	const userID = "00000000-0000-0000-0000-000000000001"
	authTime := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	authenticatedCookie := createAuthenticatedSessionCookie(t, handler, userID, authTime)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth2/logout", nil)
	req.AddCookie(authenticatedCookie)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if location := rec.Header().Get("Location"); location != "" {
		t.Fatalf("GET Location = %q, want empty", location)
	}
	if cacheControl := rec.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("GET Cache-Control = %q, want no-store", cacheControl)
	}

	confirmationCookie, confirmationSession := requireLogoutConfirmation(t, handler, rec, userID)
	challenge, ok := confirmationSession.Values[logoutConfirmationChallengeKey].(string)
	if !ok || challenge == "" {
		t.Fatal("GET did not store a logout confirmation challenge")
	}

	form := url.Values{"logout_challenge": {challenge}}
	confirmReq := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/oauth2/logout/confirm",
		strings.NewReader(form.Encode()),
	)
	confirmReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	confirmReq.AddCookie(confirmationCookie)
	confirmRec := httptest.NewRecorder()
	e.ServeHTTP(confirmRec, confirmReq)

	if confirmRec.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d, body = %s", confirmRec.Code, http.StatusOK, confirmRec.Body.String())
	}
	if !strings.Contains(confirmRec.Body.String(), "Logged out") {
		t.Fatalf("POST body does not contain completion page: %s", confirmRec.Body.String())
	}
	clearedCookie := singleResponseCookie(t, confirmRec)
	if clearedCookie.MaxAge >= 0 {
		t.Fatalf("POST session cookie MaxAge = %d, want negative", clearedCookie.MaxAge)
	}
}

func TestRPInitiatedLogoutConfirmationRejectsInvalidState(t *testing.T) {
	t.Parallel()
	handler := newRPLogoutTestHandler(nil)
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	tests := []struct {
		name   string
		mutate func(*sessions.Session)
		value  func(*sessions.Session) string
	}{
		{
			name: "wrong challenge",
			value: func(*sessions.Session) string {
				return "wrong-challenge"
			},
		},
		{
			name: "expired challenge",
			mutate: func(session *sessions.Session) {
				session.Values[logoutConfirmationExpiresAtKey] = time.Now().Add(-time.Second).Unix()
			},
		},
		{
			name: "different current session",
			mutate: func(session *sessions.Session) {
				session.Values["auth_time"] = session.Values["auth_time"].(int64) + 1
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authTime := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
			authenticatedCookie := createAuthenticatedSessionCookie(
				t,
				handler,
				"00000000-0000-0000-0000-000000000001",
				authTime,
			)

			getReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oauth2/logout", nil)
			getReq.AddCookie(authenticatedCookie)
			getRec := httptest.NewRecorder()
			e.ServeHTTP(getRec, getReq)
			confirmationCookie := singleResponseCookie(t, getRec)
			confirmationSession := readSessionCookie(t, handler, confirmationCookie)
			if test.mutate != nil {
				test.mutate(confirmationSession)
				confirmationCookie = saveSessionCookie(t, confirmationSession, confirmationCookie)
			}

			challenge := confirmationSession.Values[logoutConfirmationChallengeKey].(string)
			if test.value != nil {
				challenge = test.value(confirmationSession)
			}
			form := url.Values{"logout_challenge": {challenge}}
			postReq := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				"/oauth2/logout/confirm",
				strings.NewReader(form.Encode()),
			)
			postReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			postReq.AddCookie(confirmationCookie)
			postRec := httptest.NewRecorder()
			e.ServeHTTP(postRec, postReq)

			if postRec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d, body = %s", postRec.Code, http.StatusBadRequest, postRec.Body.String())
			}
			if setCookies := postRec.Header().Values("Set-Cookie"); len(setCookies) != 0 {
				t.Fatalf("invalid confirmation modified the session: %v", setCookies)
			}
		})
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

func newRPLogoutTestHandler(idTokenSigner fositejwt.Signer) *Handler {
	return NewHandler(nil, nil, nil, nil, OAuthConfig{
		Issuer:        "https://oidc.example.com",
		SessionSecret: []byte("test-session-secret-32-characters"), //nolint:gosec
		IDTokenSigner: idTokenSigner,
	})
}

func requireLogoutConfirmation(
	t *testing.T,
	handler *Handler,
	rec *httptest.ResponseRecorder,
	wantUserID string,
) (*http.Cookie, *sessions.Session) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Confirm logout") {
		t.Fatalf("body does not contain logout confirmation: %s", rec.Body.String())
	}

	confirmationCookie := singleResponseCookie(t, rec)
	confirmationSession := readSessionCookie(t, handler, confirmationCookie)
	if authenticated, _ := confirmationSession.Values["authenticated"].(bool); !authenticated {
		t.Fatal("current session was logged out before confirmation")
	}
	if userID, _ := confirmationSession.Values["user_id"].(string); userID != wantUserID {
		t.Fatalf("current session user_id = %q, want %q", userID, wantUserID)
	}
	return confirmationCookie, confirmationSession
}

func singleResponseCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("response cookie count = %d, want 1; headers = %v", len(cookies), rec.Header().Values("Set-Cookie"))
	}
	return cookies[0]
}

func readSessionCookie(t *testing.T, handler *Handler, cookie *http.Cookie) *sessions.Session {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	session, err := handler.sessions.Get(req, sessionName)
	if err != nil {
		t.Fatalf("failed to read session cookie: %v", err)
	}
	return session
}

func saveSessionCookie(t *testing.T, session *sessions.Session, requestCookie *http.Cookie) *http.Cookie {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(requestCookie)
	rec := httptest.NewRecorder()
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("failed to save mutated session cookie: %v", err)
	}
	return singleResponseCookie(t, rec)
}

func newTestIDTokenSigner(privateKey *rsa.PrivateKey) fositejwt.Signer {
	return &fositejwt.DefaultSigner{
		GetPrivateKey: func(context.Context) (interface{}, error) {
			return privateKey, nil
		},
	}
}
