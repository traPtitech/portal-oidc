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

func TestGetOpenIDConfigurationAdvertisesEndSessionEndpoint(t *testing.T) {
	handler := NewHandler(nil, nil, nil, nil, OAuthConfig{
		Issuer: "https://issuer.example/",
	})
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/.well-known/openid-configuration",
		nil,
	)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	var metadata gen.OpenIDConfiguration
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}

	if metadata.EndSessionEndpoint != "https://issuer.example/oauth2/logout" {
		t.Fatalf(
			"end_session_endpoint = %q, want %q",
			metadata.EndSessionEndpoint,
			"https://issuer.example/oauth2/logout",
		)
	}
}

func TestGetOAuthAuthorizationServerMetadataAdvertisesImplementedEndpoints(t *testing.T) {
	handler := NewHandler(nil, nil, nil, nil, OAuthConfig{
		Issuer: "https://issuer.example/",
	})
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/.well-known/oauth-authorization-server",
		nil,
	)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	var metadata gen.OAuthAuthorizationServerMetadata
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}

	if metadata.Issuer != "https://issuer.example/" {
		t.Fatalf("issuer = %q, want %q", metadata.Issuer, "https://issuer.example/")
	}
	if metadata.RevocationEndpoint == nil || *metadata.RevocationEndpoint != "https://issuer.example/oauth2/revoke" {
		t.Fatalf("revocation_endpoint = %v, want %q", metadata.RevocationEndpoint, "https://issuer.example/oauth2/revoke")
	}
	if metadata.IntrospectionEndpoint == nil || *metadata.IntrospectionEndpoint != "https://issuer.example/oauth2/introspect" {
		t.Fatalf("introspection_endpoint = %v, want %q", metadata.IntrospectionEndpoint, "https://issuer.example/oauth2/introspect")
	}
}

func TestGetOAuthAuthorizationServerMetadataAdvertisesOnlyIssuedGrantTypes(t *testing.T) {
	handler := NewHandler(nil, nil, nil, nil, OAuthConfig{
		Issuer: "https://issuer.example",
	})
	e := echo.New()
	gen.RegisterHandlers(e, handler)

	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"/.well-known/oauth-authorization-server",
		nil,
	)
	response := httptest.NewRecorder()
	e.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", response.Code, http.StatusOK, response.Body.String())
	}

	var metadata gen.OAuthAuthorizationServerMetadata
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}

	if metadata.GrantTypesSupported == nil {
		t.Fatal("grant_types_supported is missing")
	}
	grantTypes := *metadata.GrantTypesSupported
	if len(grantTypes) != 1 || grantTypes[0] != "authorization_code" {
		t.Fatalf("grant_types_supported = %v, want %v", grantTypes, []string{"authorization_code"})
	}
}

func TestIntegration_AuthorizeMissingResponseTypeRedirectsError(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	redirectURI := "https://client.example/callback"
	clientID := createAuthorizeTestClient(t, redirectURI)
	e := echo.New()
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
	accessTokenRepo := repository.NewAccessTokenRepository(queries)
	refreshTokenRepo := repository.NewRefreshTokenRepository(queries)

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
	if err := accessTokenRepo.Create(ctx, domain.AccessToken{
		ID:        uuid.New(),
		RequestID: signature,
		ClientID:  clientID,
		UserID:    &userID,
		JTI:       accessToken,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create access token: %v", err)
	}
	const refreshToken = "refresh-token-issued-for-reused-code"
	if err := refreshTokenRepo.Create(ctx, domain.RefreshToken{
		ID:        uuid.New(),
		RequestID: signature,
		ClientID:  clientID,
		UserID:    userID,
		TokenHash: refreshToken,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	e := echo.New()
	gen.RegisterHandlers(e, handler)
	response := exchangeAuthorizationCode(t, e, clientID.String(), clientSecret, code, redirectURI, "")
	assertTokenError(t, response, http.StatusBadRequest, gen.InvalidGrant)

	if _, err := accessTokenRepo.GetByJTI(ctx, accessToken); !errors.Is(err, repository.ErrAccessTokenNotFound) {
		t.Fatalf("access token lookup error = %v, want repository.ErrAccessTokenNotFound", err)
	}
	if _, err := refreshTokenRepo.GetByHash(ctx, refreshToken); !errors.Is(err, repository.ErrRefreshTokenNotFound) {
		t.Fatalf("refresh token lookup error = %v, want repository.ErrRefreshTokenNotFound", err)
	}
}

func TestIntegration_TokenRefreshRotationAndReuse(t *testing.T) {
	handler, cleanup := setupTestHandler(t)
	defer cleanup()

	ctx := context.Background()
	queries := oidc.New(testDB)
	clientRepo := repository.NewClientRepository(queries)
	accessTokenRepo := repository.NewAccessTokenRepository(queries)
	refreshTokenRepo := repository.NewRefreshTokenRepository(queries)

	clientID := uuid.New()
	clientSecret := "refresh-test-client-secret" //nolint:gosec // test credential
	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	if err := clientRepo.Create(ctx, &domain.Client{
		ClientID:     clientID,
		Name:         "refresh token test client",
		ClientType:   domain.ClientTypeConfidential,
		RedirectURIs: []string{"https://client.example/refresh-callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "offline_access"},
	}, string(secretHash)); err != nil {
		t.Fatalf("create client: %v", err)
	}

	strategy := compose.NewOAuth2HMACStrategy(&fosite.Config{
		GlobalSecret: []byte("test-secret-key-32-characters!!!"),
	})
	userID := uuid.New()
	// issue stores a refresh token (and an access token for the same request)
	// as if they had been issued by a previous token response.
	issue := func(t *testing.T, requestID string) (string, string) {
		t.Helper()
		refreshToken, refreshSignature, err := strategy.GenerateRefreshToken(ctx, fosite.NewRequest())
		if err != nil {
			t.Fatalf("generate refresh token: %v", err)
		}
		if err := refreshTokenRepo.Create(ctx, domain.RefreshToken{
			TokenHash: refreshSignature,
			RequestID: requestID,
			ClientID:  clientID,
			UserID:    userID,
			Scopes:    []string{"openid", "offline_access"},
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("create refresh token: %v", err)
		}
		accessJTI := "access-" + requestID
		if err := accessTokenRepo.Create(ctx, domain.AccessToken{
			JTI:       accessJTI,
			RequestID: requestID,
			ClientID:  clientID,
			UserID:    &userID,
			Scopes:    []string{"openid", "offline_access"},
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("create access token: %v", err)
		}
		return refreshToken, accessJTI
	}

	e := echo.New()
	gen.RegisterHandlers(e, handler)

	t.Run("rotation then replay revokes the family", func(t *testing.T) {
		requestID := uuid.NewString()
		oldRefresh, oldAccess := issue(t, requestID)

		response := refreshTokenGrant(ctx, t, e, clientID.String(), clientSecret, oldRefresh)
		if response.Code != http.StatusOK {
			t.Fatalf("refresh status = %d, want %d, body = %s", response.Code, http.StatusOK, response.Body.String())
		}
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.RefreshToken == "" {
			t.Fatalf("decode refresh response: %v, body = %s", err, response.Body.String())
		}

		rotated, err := refreshTokenRepo.GetByHash(ctx, strategy.RefreshTokenSignature(ctx, oldRefresh))
		if err != nil {
			t.Fatalf("get rotated refresh token: %v", err)
		}
		if rotated.RotatedAt == nil {
			t.Fatal("previous refresh token was not marked rotated")
		}
		access, err := accessTokenRepo.GetByJTI(ctx, oldAccess)
		if err != nil {
			t.Fatalf("get previous access token: %v", err)
		}
		if access.RevokedAt == nil {
			t.Fatal("access token issued before rotation was not revoked")
		}

		replay := refreshTokenGrant(ctx, t, e, clientID.String(), clientSecret, oldRefresh)
		assertTokenError(t, replay, http.StatusBadRequest, gen.InvalidGrant)

		current, err := refreshTokenRepo.GetByHash(ctx, strategy.RefreshTokenSignature(ctx, body.RefreshToken))
		if err != nil {
			t.Fatalf("get rotated-in refresh token: %v", err)
		}
		if current.RevokedAt == nil {
			t.Fatal("refresh token family was not revoked after replay")
		}
		afterReplay := refreshTokenGrant(ctx, t, e, clientID.String(), clientSecret, body.RefreshToken)
		assertTokenError(t, afterReplay, http.StatusBadRequest, gen.InvalidGrant)
	})

	t.Run("revoked refresh token is rejected", func(t *testing.T) {
		requestID := uuid.NewString()
		refreshToken, _ := issue(t, requestID)
		if err := refreshTokenRepo.RevokeByRequestID(ctx, requestID); err != nil {
			t.Fatalf("revoke refresh token: %v", err)
		}

		response := refreshTokenGrant(ctx, t, e, clientID.String(), clientSecret, refreshToken)
		assertTokenError(t, response, http.StatusBadRequest, gen.InvalidGrant)
	})
}

func refreshTokenGrant(
	ctx context.Context,
	t *testing.T,
	e *echo.Echo,
	clientID string,
	clientSecret string,
	refreshToken string,
) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.SetBasicAuth(clientID, clientSecret)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, req)
	return recorder
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
