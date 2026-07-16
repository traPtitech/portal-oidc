package v1

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
