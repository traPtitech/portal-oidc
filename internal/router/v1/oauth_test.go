package v1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"golang.org/x/crypto/bcrypt"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
)

func TestStripUnsupportedAuthorizeParameters(t *testing.T) {
	tests := []struct {
		name       string
		newRequest func(*testing.T) *http.Request
	}{
		{
			name: "GET query",
			newRequest: func(t *testing.T) *http.Request {
				t.Helper()
				return httptest.NewRequestWithContext(
					context.Background(),
					http.MethodGet,
					"/oauth2/authorize?client_id=client&request=jwt",
					nil,
				)
			},
		},
		{
			name: "URL encoded POST",
			newRequest: func(t *testing.T) *http.Request {
				t.Helper()
				form := url.Values{
					"client_id": {"client"},
					"request":   {"jwt"},
				}
				req := httptest.NewRequestWithContext(
					context.Background(),
					http.MethodPost,
					"/oauth2/authorize",
					strings.NewReader(form.Encode()),
				)
				req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
				return req
			},
		},
		{
			name: "multipart POST",
			newRequest: func(t *testing.T) *http.Request {
				t.Helper()
				return newMultipartAuthorizeRequest(t, map[string]string{
					"client_id": "client",
					"request":   "jwt",
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.newRequest(t)

			err := stripUnsupportedAuthorizeParameters(req)
			if !errors.Is(err, fosite.ErrRequestNotSupported) {
				t.Fatalf("error = %v, want ErrRequestNotSupported", err)
			}
			assertRequestObjectParametersRemoved(t, req)

			// Fosite parses multipart forms again. The unsupported values must
			// not reappear during that second parse.
			err = req.ParseMultipartForm(1 << 20)
			if err != nil && !errors.Is(err, http.ErrNotMultipart) {
				t.Fatalf("reparse request: %v", err)
			}
			assertRequestObjectParametersRemoved(t, req)
		})
	}
}

func TestStripUnsupportedAuthorizeParameters_RequestURI(t *testing.T) {
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth2/authorize?client_id=client&request_uri=https%3A%2F%2Frp.example%2Frequest.jwt",
		nil,
	)

	err := stripUnsupportedAuthorizeParameters(req)
	if !errors.Is(err, fosite.ErrRequestURINotSupported) {
		t.Fatalf("error = %v, want ErrRequestURINotSupported", err)
	}
	assertRequestObjectParametersRemoved(t, req)
}

func TestHandler_IsReauthCompleted(t *testing.T) {
	tests := []struct {
		name          string
		values        map[any]any
		wantCompleted bool
	}{
		{
			name: "authenticated after reauth marker",
			values: map[any]any{
				"reauth_requested_at": int64(100),
				"authenticated":       true,
			},
			wantCompleted: true,
		},
		{
			name: "login has not completed",
			values: map[any]any{
				"reauth_requested_at": int64(100),
				"authenticated":       false,
			},
			wantCompleted: false,
		},
		{
			name: "no reauth marker",
			values: map[any]any{
				"authenticated": true,
			},
			wantCompleted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewHandler(nil, nil, nil, nil, OAuthConfig{
				Issuer:        "http://localhost:8080",
				SessionSecret: []byte("test-session-secret-32-characters"),
			})
			ctx := contextWithSessionValues(t, handler, tt.values)

			if got := handler.isReauthCompleted(ctx); got != tt.wantCompleted {
				t.Fatalf("isReauthCompleted() = %t, want %t", got, tt.wantCompleted)
			}
		})
	}
}

func TestIntegration_AuthorizeMissingResponseTypeRedirectsError(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	redirectURI := "https://client.example/callback"
	clientID := createAuthorizeTestClient(t, redirectURI)
	e := echo.New()
	e.Use(AllowMissingAuthorizeResponseType)
	gen.RegisterHandlers(e, handler)

	query := url.Values{
		"client_id":    {clientID.String()},
		"redirect_uri": {redirectURI},
		"scope":        {"openid"},
		"state":        {"missing-response-type-state"},
	}
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth2/authorize?"+query.Encode(),
		nil,
	)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, req)

	assertAuthorizeErrorRedirect(
		t,
		response,
		redirectURI,
		"unsupported_response_type",
		"missing-response-type-state",
	)
}

func TestIntegration_AuthorizeUnsupportedRequestParameters(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	redirectURI := "https://client.example/callback"
	clientID := createAuthorizeTestClient(t, redirectURI)
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	tests := []struct {
		name      string
		parameter string
		value     string
		wantError string
	}{
		{
			name:      "request object",
			parameter: "request",
			value:     "unsigned.jwt.value",
			wantError: "request_not_supported",
		},
		{
			name:      "request URI",
			parameter: "request_uri",
			value:     "https://client.example/request.jwt",
			wantError: "request_uri_not_supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := authorizeQuery(clientID, redirectURI, tt.name)
			query.Set(tt.parameter, tt.value)
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"/oauth2/authorize?"+query.Encode(),
				nil,
			)
			response := httptest.NewRecorder()
			e.ServeHTTP(response, req)

			assertAuthorizeErrorRedirect(
				t,
				response,
				redirectURI,
				tt.wantError,
				tt.name,
			)
		})
	}
}

func TestIntegration_AuthorizeMultipartRequestObjectCannotBypassRejection(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	redirectURI := "https://client.example/callback"
	clientID := createAuthorizeTestClient(t, redirectURI)
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	req := newMultipartAuthorizeRequest(t, map[string]string{
		"client_id":     clientID.String(),
		"redirect_uri":  redirectURI,
		"response_type": "code",
		"scope":         "openid",
		"state":         "multipart-state",
		"request":       "unsigned.jwt.value",
	})
	response := httptest.NewRecorder()
	e.ServeHTTP(response, req)

	assertAuthorizeErrorRedirect(
		t,
		response,
		redirectURI,
		"request_not_supported",
		"multipart-state",
	)
}

func TestIntegration_AuthorizeRequestObjectWithoutOuterStateIsRejectedAsUnsupported(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	redirectURI := "https://client.example/callback"
	clientID := createAuthorizeTestClient(t, redirectURI)
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	query := authorizeQuery(clientID, redirectURI, "unused-state")
	query.Del("state")
	query.Set("request", "unsigned.jwt.value")
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth2/authorize?"+query.Encode(),
		nil,
	)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, req)

	assertAuthorizeErrorRedirect(
		t,
		response,
		redirectURI,
		"request_not_supported",
		"",
	)
}

func TestIntegration_AuthorizeRequestObjectDoesNotTrustInvalidOuterRedirect(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	registeredRedirectURI := "https://client.example/callback"
	clientID := createAuthorizeTestClient(t, registeredRedirectURI)
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	query := authorizeQuery(
		clientID,
		"https://attacker.example/callback",
		"invalid-redirect-state",
	)
	query.Set("request", "unsigned.jwt.value")
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/oauth2/authorize?"+query.Encode(),
		nil,
	)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, req)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"status = %d, want %d, body = %s",
			response.Code,
			http.StatusBadRequest,
			response.Body.String(),
		)
	}
	if location := response.Header().Get("Location"); location != "" {
		t.Fatalf("Location = %q, want no redirect", location)
	}
}

func TestIntegration_TokenPKCEFailureInvalidatesAuthorizationCode(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	ctx := context.Background()
	queries := oidc.New(testDB)
	clientRepo := repository.NewClientRepository(queries)
	authCodeRepo := repository.NewAuthCodeRepository(queries)

	clientID := uuid.New()
	clientSecret := "test-client-secret"
	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	redirectURI := "https://client.example/callback"
	if err := clientRepo.Create(ctx, &domain.Client{
		ClientID:     clientID,
		Name:         "PKCE failure test client",
		ClientType:   domain.ClientTypeConfidential,
		RedirectURIs: []string{redirectURI},
	}, string(secretHash)); err != nil {
		t.Fatalf("create client: %v", err)
	}

	strategy := compose.NewOAuth2HMACStrategy(&fosite.Config{
		AuthorizeCodeLifespan: 5 * time.Minute,
		GlobalSecret:          []byte("test-secret-key-32-characters!!!"),
	})
	code, signature, err := strategy.GenerateAuthorizeCode(ctx, fosite.NewRequest())
	if err != nil {
		t.Fatalf("generate authorization code: %v", err)
	}
	verifier := strings.Repeat("a", 43)
	challenge := tokenS256Challenge(verifier)
	if err := authCodeRepo.Create(ctx, domain.AuthCode{
		Code:                signature,
		ClientID:            clientID,
		UserID:              uuid.New(),
		RedirectURI:         redirectURI,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}

	e := echo.New()
	gen.RegisterHandlers(e, handler)
	wrongVerifier := strings.Repeat("b", 43)

	response := exchangeAuthorizationCode(t, e, clientID.String(), "wrong-client-secret", code, redirectURI, wrongVerifier)
	assertTokenError(t, response, http.StatusUnauthorized, gen.InvalidClient)
	assertStoredAuthorizationCode(t, authCodeRepo, signature, false, challenge, "S256")

	response = exchangeAuthorizationCode(t, e, clientID.String(), clientSecret, code, redirectURI, wrongVerifier)
	assertTokenError(t, response, http.StatusBadRequest, gen.InvalidGrant)
	assertStoredAuthorizationCode(t, authCodeRepo, signature, true, "", "")

	response = exchangeAuthorizationCode(t, e, clientID.String(), clientSecret, code, redirectURI, "")
	assertTokenError(t, response, http.StatusBadRequest, gen.InvalidGrant)

	response = exchangeAuthorizationCode(t, e, clientID.String(), clientSecret, code, redirectURI, verifier)
	assertTokenError(t, response, http.StatusBadRequest, gen.InvalidGrant)

	successCode, successSignature, err := strategy.GenerateAuthorizeCode(ctx, fosite.NewRequest())
	if err != nil {
		t.Fatalf("generate successful authorization code: %v", err)
	}
	if err := authCodeRepo.Create(ctx, domain.AuthCode{
		Code:                successSignature,
		ClientID:            clientID,
		UserID:              uuid.New(),
		RedirectURI:         redirectURI,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("create successful authorization code: %v", err)
	}

	response = exchangeAuthorizationCode(t, e, clientID.String(), clientSecret, successCode, redirectURI, verifier)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	assertStoredAuthorizationCode(t, authCodeRepo, successSignature, true, "", "")
}

func TestIntegration_TokenAuthorizationCodeReuseRevokesTokens(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	ctx := context.Background()
	queries := oidc.New(testDB)
	clientRepo := repository.NewClientRepository(queries)
	authCodeRepo := repository.NewAuthCodeRepository(queries)
	tokenRepo := repository.NewTokenRepository(queries)

	clientID := uuid.New()
	clientSecret := "reuse-test-client-secret" //nolint:gosec // test credential
	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	redirectURI := "https://client.example/reuse-callback"
	if err := clientRepo.Create(ctx, &domain.Client{
		ClientID:     clientID,
		Name:         "authorization code reuse test client",
		ClientType:   domain.ClientTypeConfidential,
		RedirectURIs: []string{redirectURI},
	}, string(secretHash)); err != nil {
		t.Fatalf("create client: %v", err)
	}

	strategy := compose.NewOAuth2HMACStrategy(&fosite.Config{
		AuthorizeCodeLifespan: 5 * time.Minute,
		GlobalSecret:          []byte("test-secret-key-32-characters!!!"),
	})
	code, signature, err := strategy.GenerateAuthorizeCode(ctx, fosite.NewRequest())
	if err != nil {
		t.Fatalf("generate authorization code: %v", err)
	}
	userID := uuid.New()
	if err := authCodeRepo.Create(ctx, domain.AuthCode{
		Code:        signature,
		ClientID:    clientID,
		UserID:      userID,
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("create authorization code: %v", err)
	}
	if err := authCodeRepo.MarkUsed(ctx, signature); err != nil {
		t.Fatalf("mark authorization code used: %v", err)
	}

	const accessToken = "access-token-issued-for-reused-code"
	if err := tokenRepo.Create(ctx, domain.Token{
		ID:          uuid.New(),
		RequestID:   signature,
		ClientID:    clientID,
		UserID:      userID,
		AccessToken: accessToken,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create token: %v", err)
	}

	e := echo.New()
	gen.RegisterHandlers(e, handler)
	response := exchangeAuthorizationCode(t, e, clientID.String(), clientSecret, code, redirectURI, "")
	assertTokenError(t, response, http.StatusBadRequest, gen.InvalidGrant)

	if _, err := tokenRepo.GetByAccessToken(ctx, accessToken); !errors.Is(err, repository.ErrTokenNotFound) {
		t.Fatalf("token lookup error = %v, want repository.ErrTokenNotFound", err)
	}
}

func exchangeAuthorizationCode(
	t *testing.T,
	e *echo.Echo,
	clientID string,
	clientSecret string,
	code string,
	redirectURI string,
	verifier string,
) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.SetBasicAuth(clientID, clientSecret)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, req)
	return recorder
}

func assertTokenError(t *testing.T, response *httptest.ResponseRecorder, status int, want gen.OAuthErrorError) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d, body = %s", response.Code, status, response.Body.String())
	}
	var body gen.OAuthError
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode OAuth error: %v", err)
	}
	if body.Error != want {
		t.Fatalf("OAuth error = %q, want %q", body.Error, want)
	}
}

func assertStoredAuthorizationCode(
	t *testing.T,
	repo repository.AuthCodeRepository,
	code string,
	used bool,
	challenge string,
	method string,
) {
	t.Helper()
	stored, err := repo.Get(context.Background(), code)
	if err != nil {
		t.Fatalf("get authorization code: %v", err)
	}
	if stored.Used != used {
		t.Fatalf("used = %t, want %t", stored.Used, used)
	}
	if stored.CodeChallenge != challenge {
		t.Fatalf("code challenge = %q, want %q", stored.CodeChallenge, challenge)
	}
	if stored.CodeChallengeMethod != method {
		t.Fatalf("code challenge method = %q, want %q", stored.CodeChallengeMethod, method)
	}
}

func tokenS256Challenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func newMultipartAuthorizeRequest(
	t *testing.T,
	fields map[string]string,
) *http.Request {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("write multipart field %s: %v", key, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/oauth2/authorize",
		&body,
	)
	req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
	return req
}

func assertRequestObjectParametersRemoved(t *testing.T, req *http.Request) {
	t.Helper()

	for _, key := range []string{"request", "request_uri"} {
		if value := req.Form.Get(key); value != "" {
			t.Errorf("Form[%q] = %q, want empty", key, value)
		}
		if value := req.PostForm.Get(key); value != "" {
			t.Errorf("PostForm[%q] = %q, want empty", key, value)
		}
		if req.MultipartForm != nil {
			if values := req.MultipartForm.Value[key]; len(values) != 0 {
				t.Errorf("MultipartForm.Value[%q] = %q, want empty", key, values)
			}
		}
	}
}

func contextWithSessionValues(
	t *testing.T,
	handler *Handler,
	values map[any]any,
) *echo.Context {
	t.Helper()

	e := echo.New()
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/",
		nil,
	)
	recorder := httptest.NewRecorder()
	session, err := handler.sessions.Get(req, sessionName)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	for key, value := range values {
		session.Values[key] = value
	}
	if err := session.Save(req, recorder); err != nil {
		t.Fatalf("save session: %v", err)
	}

	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("session cookies = %d, want 1", len(cookies))
	}
	nextRequest := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/",
		nil,
	)
	nextRequest.AddCookie(cookies[0])
	return e.NewContext(nextRequest, httptest.NewRecorder())
}

func createAuthorizeTestClient(t *testing.T, redirectURI string) uuid.UUID {
	t.Helper()

	clientID := uuid.New()
	secretHash, err := bcrypt.GenerateFromPassword(
		[]byte("authorize-test-client-secret"),
		bcrypt.MinCost,
	)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	clientRepo := repository.NewClientRepository(oidc.New(testDB))
	if err := clientRepo.Create(context.Background(), &domain.Client{
		ClientID:     clientID,
		Name:         "authorize test client",
		ClientType:   domain.ClientTypeConfidential,
		RedirectURIs: []string{redirectURI},
	}, string(secretHash)); err != nil {
		t.Fatalf("create authorize test client: %v", err)
	}
	return clientID
}

func authorizeQuery(
	clientID uuid.UUID,
	redirectURI string,
	state string,
) url.Values {
	return url.Values{
		"client_id":     {clientID.String()},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {state},
	}
}

func assertAuthorizeErrorRedirect(
	t *testing.T,
	response *httptest.ResponseRecorder,
	redirectURI string,
	wantError string,
	wantState string,
) {
	t.Helper()

	if response.Code != http.StatusSeeOther {
		t.Fatalf(
			"status = %d, want %d, body = %s",
			response.Code,
			http.StatusSeeOther,
			response.Body.String(),
		)
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	wantLocation, err := url.Parse(redirectURI)
	if err != nil {
		t.Fatalf("parse expected redirect URI: %v", err)
	}
	if location.Scheme != wantLocation.Scheme ||
		location.Host != wantLocation.Host ||
		location.Path != wantLocation.Path {
		t.Fatalf("redirect target = %q, want %q", location, wantLocation)
	}
	if got := location.Query().Get("error"); got != wantError {
		t.Fatalf("error = %q, want %q", got, wantError)
	}
	if got := location.Query().Get("state"); got != wantState {
		t.Fatalf("state = %q, want %q", got, wantState)
	}
}
