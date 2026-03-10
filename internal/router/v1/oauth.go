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
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/repository/oauth"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

func (h *Handler) GetAuthorize(ctx echo.Context, params gen.GetAuthorizeParams) error {
	return h.authorize(ctx)
}

func (h *Handler) PostAuthorize(ctx echo.Context) error {
	return h.authorize(ctx)
}

func (h *Handler) authorize(ctx echo.Context) error {
	c := ctx.Request().Context()
	rw := ctx.Response()
	req := ctx.Request()

	ar, err := h.oauth2.NewAuthorizeRequest(c, req)
	if err != nil {
		h.oauth2.WriteAuthorizeError(c, rw, ar, err)
		return nil
	}

	returnURL := req.URL.String()
	info, authenticated := h.getAuthInfo(ctx)

	action := h.oauthUseCase.EvaluateAuthorize(usecase.AuthorizeInput{
		Prompt:          ar.GetRequestForm().Get("prompt"),
		Authenticated:   authenticated,
		AuthTime:        info.AuthTime,
		MaxAge:          parseMaxAge(ar),
		ReauthCompleted: h.isReauthCompleted(ctx, info.AuthTime),
		IsNonProd:       h.config.Environment != "production",
	})

	switch action {
	case usecase.AuthorizeActionLoginError:
		h.oauth2.WriteAuthorizeError(c, rw, ar, fosite.ErrLoginRequired)
		return nil
	case usecase.AuthorizeActionLogin:
		return h.redirectToLogin(ctx, returnURL)
	}

	userID := info.UserID
	authTime := info.AuthTime
	if h.config.Environment != "production" {
		userID = h.config.TestUserID
		authTime = time.Now()
	}

	return h.completeAuthorize(ctx, ar, userID, authTime)
}

func (h *Handler) completeAuthorize(ctx echo.Context, ar fosite.AuthorizeRequester, userID string, authTime time.Time) error {
	c := ctx.Request().Context()
	rw := ctx.Response()

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

func (h *Handler) isReauthCompleted(ctx echo.Context, authTime time.Time) bool {
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

func (h *Handler) redirectToLogin(ctx echo.Context, returnURL string) error {
	session, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get session")
	}

	session.Values["reauth_requested_at"] = time.Now().Unix()
	session.Values["authenticated"] = false

	if err := session.Save(ctx.Request(), ctx.Response()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save session")
	}

	return ctx.Redirect(http.StatusFound, "/login?return_url="+url.QueryEscape(returnURL))
}

// parseMaxAge returns the max_age parameter as a pointer.
// Returns nil if the parameter is absent or not a valid integer,
// since max_age is an OPTIONAL parameter in OpenID Connect Core 1.0 (Section 3.1.2.1).
// The value is extracted via fosite's GetRequestForm() (not oapi-codegen's auto-binding)
// because fosite reads from http.Request.Form which unifies GET query params and POST form body.
func parseMaxAge(ar fosite.AuthorizeRequester) *int64 {
	maxAgeStr := ar.GetRequestForm().Get("max_age")
	if maxAgeStr == "" {
		return nil
	}
	maxAge, err := strconv.ParseInt(maxAgeStr, 10, 64)
	if err != nil {
		return nil
	}
	return &maxAge
}

func (h *Handler) Token(ctx echo.Context) error {
	c := ctx.Request().Context()
	rw := ctx.Response()
	req := ctx.Request()

	session := oauth.NewSession("", time.Time{})
	accessRequest, err := h.oauth2.NewAccessRequest(c, req, session)
	if err != nil {
		h.oauth2.WriteAccessError(c, rw, accessRequest, err)
		return nil
	}

	for _, scope := range accessRequest.GetRequestedScopes() {
		accessRequest.GrantScope(scope)
	}

	response, err := h.oauth2.NewAccessResponse(c, accessRequest)
	if err != nil {
		h.oauth2.WriteAccessError(c, rw, accessRequest, err)
		return nil
	}

	h.oauth2.WriteAccessResponse(c, rw, accessRequest, response)
	return nil
}

func (h *Handler) GetUserInfo(ctx echo.Context) error {
	token, err := h.extractBearerToken(ctx)
	if err != nil {
		return ctx.JSON(http.StatusUnauthorized, gen.OAuthError{Error: gen.InvalidRequest})
	}
	return h.handleUserInfo(ctx, token)
}

func (h *Handler) PostUserInfo(ctx echo.Context) error {
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

func (h *Handler) extractBearerToken(ctx echo.Context) (string, error) {
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

func (h *Handler) handleUserInfo(ctx echo.Context, token string) error {
	c := ctx.Request().Context()

	_, ar, err := h.oauth2.IntrospectToken(c, token, fosite.AccessToken, oauth.NewSession("", time.Time{}))
	if err != nil {
		return ctx.JSON(http.StatusUnauthorized, gen.OAuthError{Error: gen.InvalidGrant})
	}

	sub := ar.GetSession().GetSubject()
	info := gen.UserInfo{Sub: sub}

	if h.userUseCase != nil && ar.GetGrantedScopes().Has("profile") {
		user, userErr := h.userUseCase.GetByID(c, sub)
		if userErr == nil {
			info.Name = &user.TrapID
			info.PreferredUsername = &user.TrapID
		}
	}

	return ctx.JSON(http.StatusOK, info)
}

func (h *Handler) GetJWKS(ctx echo.Context) error {
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

func (h *Handler) GetOpenIDConfiguration(ctx echo.Context) error {
	issuer := strings.TrimRight(h.config.Issuer, "/")
	scopesSupported := []string{"openid", "profile", "email"}
	claimsSupported := []string{"sub", "name", "preferred_username", "email", "email_verified"}
	codeChallengeMethodsSupported := []string{"S256", "plain"}
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
