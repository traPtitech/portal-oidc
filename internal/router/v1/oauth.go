package v1

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/repository/oauth"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

func (h *Handler) GetAuthorize(ctx *echo.Context, params gen.GetAuthorizeParams) error {
	return h.authorize(ctx)
}

func (h *Handler) PostAuthorize(ctx *echo.Context) error {
	return h.authorize(ctx)
}

func (h *Handler) authorize(ctx *echo.Context) error {
	c := ctx.Request().Context()
	rw := ctx.Response()
	req := ctx.Request()

	ar, err := h.oauth2.NewAuthorizeRequest(c, req)
	if err != nil {
		h.oauth2.WriteAuthorizeError(c, rw, ar, err)
		return nil
	}

	// Copy req.URL to avoid unintended mutation of the original request URL.
	// RawQuery is overwritten with fosite's merged form values (GET query + POST body)
	// so that POST parameters are preserved when redirecting back via GET after login.
	returnURL := *req.URL
	returnURL.RawQuery = ar.GetRequestForm().Encode()

	info, authenticated := h.getAuthInfo(ctx)

	maxAge, err := parseMaxAge(ar)
	if err != nil {
		h.oauth2.WriteAuthorizeError(c, rw, ar, fosite.ErrInvalidRequest.WithHint("invalid max_age parameter").WithDebug(err.Error()))
		return nil
	}

	action := h.oauthUseCase.EvaluateAuthorize(usecase.AuthorizeInput{
		Prompt:          ar.GetRequestForm().Get("prompt"),
		Authenticated:   authenticated,
		AuthTime:        info.AuthTime,
		MaxAge:          maxAge,
		ReauthCompleted: h.isReauthCompleted(ctx, info.AuthTime),
	})

	if action == usecase.AuthorizeActionInvalidRequest {
		h.oauth2.WriteAuthorizeError(c, rw, ar, fosite.ErrInvalidRequest.WithHint("Parameter 'prompt' was set to 'none', but contains other values as well which is not allowed."))
		return nil
	}
	if action == usecase.AuthorizeActionLoginError {
		h.oauth2.WriteAuthorizeError(c, rw, ar, fosite.ErrLoginRequired)
		return nil
	}
	if action == usecase.AuthorizeActionLogin {
		return h.redirectToLogin(ctx, &returnURL)
	}

	return h.completeAuthorize(ctx, ar, info.UserID, info.AuthTime)
}

func (h *Handler) completeAuthorize(ctx *echo.Context, ar fosite.AuthorizeRequester, userID string, authTime time.Time) error {
	c := ctx.Request().Context()
	rw := ctx.Response()

	if err := h.clearReauthRequest(ctx); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save session")
	}

	session := oauth.NewSession(userID, authTime)
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	response, err := h.oauth2.NewAuthorizeResponse(c, ar, session)
	if err != nil {
		h.oauth2.WriteAuthorizeError(c, rw, ar, err)
		return nil
	}

	h.oauth2.WriteAuthorizeResponse(c, rw, ar, response)
	return nil
}

func (h *Handler) isReauthCompleted(ctx *echo.Context, authTime time.Time) bool {
	session, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return false
	}

	reqAt, ok := session.Values["reauth_requested_at"].(int64)
	if !ok {
		return false
	}

	return authTime.Unix() > reqAt
}

func (h *Handler) clearReauthRequest(ctx *echo.Context) error {
	session, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return err
	}

	if _, ok := session.Values["reauth_requested_at"]; !ok {
		return nil
	}

	delete(session.Values, "reauth_requested_at")
	return session.Save(ctx.Request(), ctx.Response())
}

func (h *Handler) redirectToLogin(ctx *echo.Context, returnURL *url.URL) error {
	session, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get session")
	}

	session.Values["reauth_requested_at"] = time.Now().Unix()
	session.Values["authenticated"] = false

	if err := session.Save(ctx.Request(), ctx.Response()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save session")
	}

	return ctx.Redirect(http.StatusFound, "/login?return_url="+url.QueryEscape(returnURL.String()))
}

// parseMaxAge returns the max_age parameter as a pointer.
// Returns nil if the parameter is absent or not a valid integer,
// since max_age is an OPTIONAL parameter in OpenID Connect Core 1.0 (Section 3.1.2.1).
// The value is extracted via fosite's GetRequestForm() (not oapi-codegen's auto-binding)
// because fosite reads from http.Request.Form which unifies GET query params and POST form body.
func parseMaxAge(ar fosite.AuthorizeRequester) (*int64, error) {
	maxAgeStr := ar.GetRequestForm().Get("max_age")
	if maxAgeStr == "" {
		// max_age is optional, so return nil if it's not present or empty.
		//nolint:nilnil
		return nil, nil
	}

	maxAge, err := strconv.ParseInt(maxAgeStr, 10, 64)
	if err != nil {
		return nil, err
	}

	if maxAge < 0 {
		return nil, errors.New("max_age must be non-negative")
	}

	return &maxAge, nil
}

func (h *Handler) Token(ctx *echo.Context) error {
	result, err := h.oauthUseCase.ProcessToken(
		ctx.Request().Context(),
		ctx.Request(),
		oauth.NewSession("", time.Time{}),
	)
	if err != nil {
		h.oauth2.WriteAccessError(result.Context, ctx.Response(), result.Request, err)
		return nil
	}

	h.oauth2.WriteAccessResponse(result.Context, ctx.Response(), result.Request, result.Response)
	return nil
}

func (h *Handler) GetUserInfo(ctx *echo.Context) error {
	token, err := h.extractBearerToken(ctx)
	if err != nil {
		return ctx.JSON(http.StatusUnauthorized, gen.OAuthError{Error: gen.InvalidRequest})
	}
	return h.handleUserInfo(ctx, token)
}

func (h *Handler) PostUserInfo(ctx *echo.Context) error {
	// RFC 6750: POST can use Authorization header OR form body
	token, err := h.extractBearerToken(ctx)
	if err != nil {
		// Try form body (application/x-www-form-urlencoded)
		token = ctx.FormValue("access_token")
		if token == "" {
			return ctx.JSON(http.StatusUnauthorized, gen.OAuthError{Error: gen.InvalidRequest})
		}
	}
	return h.handleUserInfo(ctx, token)
}

func (h *Handler) extractBearerToken(ctx *echo.Context) (string, error) {
	authHeader := ctx.Request().Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no authorization header")
	}

	// RFC 6750: The access token type is case-insensitive
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return authHeader[7:], nil // len("bearer ") == 7
	}
	return "", errors.New("invalid authorization header")
}

func (h *Handler) handleUserInfo(ctx *echo.Context, token string) error {
	c := ctx.Request().Context()

	_, ar, err := h.oauth2.IntrospectToken(c, token, fosite.AccessToken, oauth.NewSession("", time.Time{}))
	if err != nil {
		return ctx.JSON(http.StatusUnauthorized, gen.OAuthError{Error: gen.InvalidGrant})
	}

	sub := ar.GetSession().GetSubject()
	info := gen.UserInfo{Sub: sub}

	if h.userUseCase != nil && ar.GetGrantedScopes().Has("profile") {
		subID, err := uuid.Parse(sub)
		if err != nil {

			return ctx.JSON(http.StatusUnauthorized, gen.OAuthError{Error: gen.InvalidGrant})
		}
		user, userErr := h.userUseCase.GetByID(c, subID)
		if userErr != nil {
			return ctx.JSON(http.StatusInternalServerError, gen.OAuthError{Error: gen.ServerError})
		}
		info.Name = &user.TrapID
		info.PreferredUsername = &user.TrapID
	}

	return ctx.JSON(http.StatusOK, info)
}

func (h *Handler) GetJWKS(ctx *echo.Context) error {
	if h.config.PrivateKey == nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "signing key not configured")
	}
	pubKey := &h.config.PrivateKey.PublicKey

	hash := sha256.Sum256(pubKey.N.Bytes())
	kid := base64.RawURLEncoding.EncodeToString(hash[:8])

	jwk := jose.JSONWebKey{
		Key:       pubKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"keys": []jose.JSONWebKey{jwk},
	})
}

func (h *Handler) GetOpenIDConfiguration(ctx *echo.Context) error {
	issuer := strings.TrimRight(h.config.Issuer, "/")
	scopesSupported := []string{"openid", "profile", "email"}
	claimsSupported := []string{"sub", "name", "preferred_username", "email", "email_verified"}
	// OAuth 2.1 §1.4.2 / fosite EnablePKCEPlainChallengeMethod=false: only S256 is
	// honoured by the server, so advertising "plain" would only invite downgrades.
	codeChallengeMethodsSupported := []string{"S256"}
	tokenEndpointAuthMethodsSupported := []string{"client_secret_basic", "client_secret_post"}

	return ctx.JSON(http.StatusOK, gen.OpenIDConfiguration{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/oauth2/authorize",
		TokenEndpoint:                     issuer + "/oauth2/token",
		UserinfoEndpoint:                  issuer + "/oauth2/userinfo",
		JwksUri:                           issuer + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IdTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   &scopesSupported,
		ClaimsSupported:                   &claimsSupported,
		CodeChallengeMethodsSupported:     &codeChallengeMethodsSupported,
		TokenEndpointAuthMethodsSupported: &tokenEndpointAuthMethodsSupported,
	})
}

// GetOAuthAuthorizationServerMetadata serves the RFC 8414 metadata document.
// Compared to OIDC discovery this strips OIDC-only fields (subject_types_supported,
// id_token_signing_alg_values_supported, claims_supported) and adds OAuth-only ones
// (response_modes_supported, grant_types_supported).
//
// Refs:
//   - RFC 8414 §2 (Authorization Server Metadata)
//     https://datatracker.ietf.org/doc/html/rfc8414#section-2
//   - RFC 8414 §3.1 (.well-known/oauth-authorization-server)
//     https://datatracker.ietf.org/doc/html/rfc8414#section-3.1
func (h *Handler) GetOAuthAuthorizationServerMetadata(ctx *echo.Context) error {
	issuer := strings.TrimRight(h.config.Issuer, "/")
	jwksURI := issuer + "/.well-known/jwks.json"
	scopesSupported := []string{"openid", "profile", "email"}
	grantTypesSupported := []string{"authorization_code", "refresh_token"}
	responseModesSupported := []string{"query"}
	// OAuth 2.1 (draft) §1.4.2: clients SHOULD use a code_challenge method that
	// does not expose the verifier in the authorization request, and S256 is the
	// only such method. fosite is configured with EnablePKCEPlainChallengeMethod=false
	// in cmd/oauth.go so the server never accepts "plain" anyway; advertising it
	// here would only invite downgrade attempts.
	codeChallengeMethodsSupported := []string{"S256"}
	tokenEndpointAuthMethodsSupported := []string{"client_secret_basic", "client_secret_post"}

	return ctx.JSON(http.StatusOK, gen.OAuthAuthorizationServerMetadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/oauth2/authorize",
		TokenEndpoint:                     issuer + "/oauth2/token",
		JwksUri:                           &jwksURI,
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            &responseModesSupported,
		GrantTypesSupported:               &grantTypesSupported,
		ScopesSupported:                   &scopesSupported,
		CodeChallengeMethodsSupported:     &codeChallengeMethodsSupported,
		TokenEndpointAuthMethodsSupported: &tokenEndpointAuthMethodsSupported,
	})
}
