package v1

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo/v5"
	"github.com/oapi-codegen/runtime"
	fositejwt "github.com/ory/fosite/token/jwt"

	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

const (
	sessionName = "oidc_session"

	logoutConfirmationChallengeKey = "logout_confirmation_challenge"
	logoutConfirmationUserIDKey    = "logout_confirmation_user_id"
	logoutConfirmationAuthTimeKey  = "logout_confirmation_auth_time"
	logoutConfirmationExpiresAtKey = "logout_confirmation_expires_at"
	logoutConfirmationTTL          = 5 * time.Minute
	logoutConfirmationBytes        = 32
)

var (
	errInvalidIDTokenHint               = errors.New("invalid id_token_hint")
	errIDTokenHintValidationUnavailable = errors.New("id_token_hint validation unavailable")
)

func (h *Handler) GetLogin(ctx *echo.Context) error {
	returnURL := sanitizeReturnURL(ctx.QueryParam("return_url"))

	devNote := ""
	if h.config.Environment != "production" {
		devNote = `<p style="color: gray; font-size: 12px;">Test user: testuser / password</p>`
	}

	page := `<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        form { display: flex; flex-direction: column; gap: 10px; }
        input { padding: 10px; font-size: 16px; }
        button { padding: 10px; font-size: 16px; background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h1>Login</h1>
    <form method="POST" action="/login">
        <input type="hidden" name="return_url" value="` + html.EscapeString(returnURL) + `">
        <input type="text" name="username" placeholder="traP ID" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    ` + devNote + `
</body>
</html>`

	return ctx.HTML(http.StatusOK, page)
}

func (h *Handler) PostLogin(ctx *echo.Context) error {
	username := ctx.FormValue("username")
	password := ctx.FormValue("password")
	returnURL := ctx.FormValue("return_url")

	var userID string
	var err error

	if h.config.Environment != "production" {
		userID, err = h.authenticateTestUser(username, password)
	} else {
		userID, err = h.authenticatePortalUser(ctx, username, password)
	}

	if err != nil {
		return ctx.HTML(http.StatusUnauthorized, `<!DOCTYPE html>
<html>
<head><title>Login Failed</title></head>
<body>
    <h1>Login Failed</h1>
    <p>Invalid username or password.</p>
    <a href="/login?return_url=`+html.EscapeString(returnURL)+`">Try again</a>
</body>
</html>`)
	}

	session, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get session")
	}

	session.Values["user_id"] = userID
	session.Values["authenticated"] = true
	session.Values["auth_time"] = time.Now().Unix()
	clearLogoutConfirmation(session)

	if err := session.Save(ctx.Request(), ctx.Response()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save session")
	}

	return ctx.Redirect(http.StatusFound, sanitizeReturnURL(returnURL))
}

func (h *Handler) authenticateTestUser(username, password string) (string, error) {
	if username == "testuser" && password == "password" {
		return h.config.TestUserID, nil
	}
	return "", errors.New("invalid credentials")
}

func (h *Handler) authenticatePortalUser(ctx *echo.Context, trapID, password string) (string, error) {
	user, err := h.userUseCase.Authenticate(ctx.Request().Context(), trapID, password)
	if err != nil {
		if errors.Is(err, usecase.ErrUserNotFound) ||
			errors.Is(err, usecase.ErrInvalidPassword) ||
			errors.Is(err, usecase.ErrUserNotActive) {
			return "", errors.New("authentication failed")
		}
		return "", err
	}

	return user.ID.String(), nil
}

func (h *Handler) Logout(ctx *echo.Context) error {
	if err := h.clearSession(ctx); err != nil {
		return err
	}
	return ctx.Redirect(http.StatusFound, "/")
}

// RPInitiatedLogout implements OpenID Connect RP-Initiated Logout 1.0.
//
// Steps:
//  1. Verify id_token_hint signature and claims (if provided) using the OP's
//     signing key and the current OP session.
//  2. If the hint is absent or does not identify the current session, issue a
//     short-lived confirmation challenge instead of changing the session.
//  3. Terminate the End-User's session only after a trusted hint or explicit
//     confirmation.
//  4. If post_logout_redirect_uri was supplied AND it matches a URI registered
//     for the client identified by id_token_hint.aud (or the explicit client_id
//     query parameter), redirect there with the optional state echoed back.
//  5. Otherwise render a simple completion page.
//
// post_logout_redirect_uri validation is intentionally strict: clients without
// a pre-registered URI are not redirected to arbitrary external locations,
// matching the open-redirect mitigation in the spec. The clients table does
// not yet carry post_logout_uris (Phase 2.1), so for now any external URI is
// rejected and the local completion page is shown.
//
// Refs:
//   - OpenID Connect RP-Initiated Logout 1.0 §2 (Logout Request)
//     https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
//   - OpenID Connect RP-Initiated Logout 1.0 §3 (Redirect URI Validation)
//     https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling
func (h *Handler) GetRPInitiatedLogout(ctx *echo.Context, params gen.GetRPInitiatedLogoutParams) error {
	return h.rpInitiatedLogout(ctx, params)
}

// PostRPInitiatedLogout accepts Logout Request parameters using HTML Form
// Serialization, as required by OpenID Connect RP-Initiated Logout 1.0.
func (h *Handler) PostRPInitiatedLogout(ctx *echo.Context) error {
	if err := ctx.Request().ParseForm(); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid RP-initiated logout form")
	}

	var body gen.PostRPInitiatedLogoutFormdataRequestBody
	if err := runtime.BindForm(&body, ctx.Request().PostForm, nil, nil); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid RP-initiated logout form")
	}

	return h.rpInitiatedLogout(ctx, gen.GetRPInitiatedLogoutParams{
		IdTokenHint:           body.IdTokenHint,
		PostLogoutRedirectUri: body.PostLogoutRedirectUri,
		ClientId:              body.ClientId,
		State:                 body.State,
		UiLocales:             body.UiLocales,
	})
}

func (h *Handler) rpInitiatedLogout(ctx *echo.Context, params gen.GetRPInitiatedLogoutParams) error {
	idTokenHint := ""
	if params.IdTokenHint != nil {
		idTokenHint = *params.IdTokenHint
	}

	postLogoutRedirectURI := ""
	if params.PostLogoutRedirectUri != nil {
		postLogoutRedirectURI = *params.PostLogoutRedirectUri
	}

	state := ""
	if params.State != nil {
		state = *params.State
	}

	currentSession, authenticated := h.getAuthInfo(ctx)
	if idTokenHint == "" {
		if !authenticated {
			return renderLoggedOutPage(ctx)
		}
		return h.renderLogoutConfirmation(ctx, currentSession)
	}

	clientID := ""
	if params.ClientId != nil {
		clientID = params.ClientId.String()
	}

	var sessionInfo *authInfo
	if authenticated {
		sessionInfo = &currentSession
	}

	err := h.validateRPLogoutIDTokenHint(
		ctx.Request().Context(),
		idTokenHint,
		clientID,
		sessionInfo,
	)
	if err != nil {
		if errors.Is(err, errInvalidIDTokenHint) && authenticated {
			return h.renderLogoutConfirmation(ctx, currentSession)
		}
		if errors.Is(err, errInvalidIDTokenHint) {
			return echo.NewHTTPError(http.StatusBadRequest, errInvalidIDTokenHint.Error())
		}
		if errors.Is(err, errIDTokenHintValidationUnavailable) {
			return echo.NewHTTPError(http.StatusInternalServerError, errIDTokenHintValidationUnavailable.Error())
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to validate id_token_hint audience")
	}

	if err := h.clearSession(ctx); err != nil {
		return err
	}

	if postLogoutRedirectURI != "" {
		// TODO(Phase 2.1): once clients.post_logout_uris is added, look up the
		// client by id_token_hint.aud or client_id and verify exact match here.
		// For now we always render the local completion page to avoid open redirects.
		_ = state
	}

	return renderLoggedOutPage(ctx)
}

func (h *Handler) validateRPLogoutIDTokenHint(
	ctx context.Context,
	rawToken string,
	clientID string,
	currentSession *authInfo,
) error {
	if h.config.IDTokenSigner == nil {
		return errIDTokenHintValidationUnavailable
	}

	audiences, err := validateIDTokenHint(
		ctx,
		rawToken,
		h.config.IDTokenSigner,
		h.config.Issuer,
		clientID,
		currentSession,
	)
	if err != nil {
		return errInvalidIDTokenHint
	}

	registered, err := h.hasRegisteredAudience(ctx, audiences)
	if err != nil {
		return err
	}
	if !registered {
		return errInvalidIDTokenHint
	}
	return nil
}

// PostRPInitiatedLogoutConfirmation completes a logout request that could not
// be safely bound to the current OP session from an ID Token hint alone.
func (h *Handler) PostRPInitiatedLogoutConfirmation(ctx *echo.Context) error {
	session, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get session")
	}

	if !validLogoutConfirmation(session, ctx.FormValue("logout_challenge"), time.Now()) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid logout confirmation")
	}

	if err := h.clearSession(ctx); err != nil {
		return err
	}
	return renderLoggedOutPage(ctx)
}

func (h *Handler) renderLogoutConfirmation(ctx *echo.Context, currentSession authInfo) error {
	challenge, err := newLogoutConfirmationChallenge()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create logout confirmation")
	}

	session, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get session")
	}
	session.Values[logoutConfirmationChallengeKey] = challenge
	session.Values[logoutConfirmationUserIDKey] = currentSession.UserID
	session.Values[logoutConfirmationAuthTimeKey] = currentSession.AuthTime.Unix()
	session.Values[logoutConfirmationExpiresAtKey] = time.Now().Add(logoutConfirmationTTL).Unix()
	if err := session.Save(ctx.Request(), ctx.Response()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save logout confirmation")
	}

	setLogoutPageHeaders(ctx)
	return ctx.HTML(http.StatusOK, `<!DOCTYPE html>
<html>
<head>
    <title>Confirm logout</title>
    <style>
        body { font-family: sans-serif; max-width: 480px; margin: 100px auto; padding: 20px; }
        form { display: inline; }
        button, a { display: inline-block; margin-right: 8px; padding: 10px 16px; font-size: 16px; }
        button { background: #c62828; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Sign out?</h1>
    <p>A logout request could not be verified as belonging to your current session.</p>
    <form method="POST" action="/oauth2/logout/confirm">
        <input type="hidden" name="logout_challenge" value="`+html.EscapeString(challenge)+`">
        <button type="submit">Sign out</button>
    </form>
    <a href="/">Stay signed in</a>
</body>
</html>`)
}

func newLogoutConfirmationChallenge() (string, error) {
	random := make([]byte, logoutConfirmationBytes)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func validLogoutConfirmation(session *sessions.Session, suppliedChallenge string, now time.Time) bool {
	storedChallenge, challengeOK := session.Values[logoutConfirmationChallengeKey].(string)
	targetUserID, userIDOK := session.Values[logoutConfirmationUserIDKey].(string)
	targetAuthTime, targetAuthTimeOK := session.Values[logoutConfirmationAuthTimeKey].(int64)
	expiresAt, expiresAtOK := session.Values[logoutConfirmationExpiresAtKey].(int64)
	authenticated, authenticatedOK := session.Values["authenticated"].(bool)
	currentUserID, currentUserIDOK := session.Values["user_id"].(string)
	currentAuthTime, currentAuthTimeOK := session.Values["auth_time"].(int64)

	if suppliedChallenge == "" || !challengeOK || !userIDOK || !targetAuthTimeOK || !expiresAtOK ||
		!authenticatedOK || !authenticated || !currentUserIDOK || !currentAuthTimeOK ||
		now.Unix() >= expiresAt || targetUserID != currentUserID || targetAuthTime != currentAuthTime {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(storedChallenge), []byte(suppliedChallenge)) == 1
}

func clearLogoutConfirmation(session *sessions.Session) {
	delete(session.Values, logoutConfirmationChallengeKey)
	delete(session.Values, logoutConfirmationUserIDKey)
	delete(session.Values, logoutConfirmationAuthTimeKey)
	delete(session.Values, logoutConfirmationExpiresAtKey)
}

func renderLoggedOutPage(ctx *echo.Context) error {
	setLogoutPageHeaders(ctx)
	return ctx.HTML(http.StatusOK, `<!DOCTYPE html>
<html>
<head><title>Logged out</title></head>
<body>
    <h1>Logged out</h1>
    <p>You have been signed out.</p>
</body>
</html>`)
}

func setLogoutPageHeaders(ctx *echo.Context) {
	ctx.Response().Header().Set("Cache-Control", "no-store")
	ctx.Response().Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	ctx.Response().Header().Set("X-Frame-Options", "DENY")
}

func validateIDTokenHint(
	ctx context.Context,
	rawToken string,
	signer fositejwt.Signer,
	issuer string,
	clientID string,
	currentSession *authInfo,
) ([]string, error) {
	claims, expired, err := decodeIDTokenHint(ctx, signer, rawToken)
	if err != nil {
		return nil, err
	}

	audiences, err := validateIDTokenHintClaims(claims, issuer, clientID)
	if err != nil {
		return nil, err
	}
	if err := validateIDTokenHintSession(claims, expired, currentSession); err != nil {
		return nil, err
	}

	return audiences, nil
}

func decodeIDTokenHint(
	ctx context.Context,
	signer fositejwt.Signer,
	rawToken string,
) (fositejwt.MapClaims, bool, error) {
	token, err := signer.Decode(ctx, rawToken)
	expired := false
	if err != nil {
		var validationErr *fositejwt.ValidationError
		if !errors.As(err, &validationErr) || validationErr.Errors != fositejwt.ValidationErrorExpired {
			return nil, false, err
		}
		expired = true
	}
	if token == nil {
		return nil, false, errors.New("id_token_hint could not be decoded")
	}
	return token.Claims, expired, nil
}

func validateIDTokenHintClaims(
	claims fositejwt.MapClaims,
	issuer string,
	clientID string,
) ([]string, error) {
	issuerClaim, issuerOK := requiredStringClaim(claims, "iss")
	if issuer == "" || !issuerOK || issuerClaim != issuer {
		return nil, errors.New("id_token_hint has invalid issuer")
	}
	if _, subjectOK := requiredStringClaim(claims, "sub"); !subjectOK {
		return nil, errors.New("id_token_hint has invalid subject")
	}

	audiences, audienceOK := stringListClaim(claims, "aud")
	if !audienceOK {
		return nil, errors.New("id_token_hint has invalid audience")
	}
	if clientID != "" && !slices.Contains(audiences, clientID) {
		return nil, errors.New("id_token_hint audience does not match client_id")
	}
	if _, expiryOK := numericDateClaim(claims, "exp"); !expiryOK {
		return nil, errors.New("id_token_hint has invalid expiration")
	}
	if _, issuedAtOK := numericDateClaim(claims, "iat"); !issuedAtOK {
		return nil, errors.New("id_token_hint has invalid issued-at time")
	}
	return audiences, nil
}

func validateIDTokenHintSession(
	claims fositejwt.MapClaims,
	expired bool,
	currentSession *authInfo,
) error {
	if currentSession == nil {
		if expired {
			return errors.New("expired id_token_hint does not identify a current OP session")
		}
		return nil
	}

	subject, _ := requiredStringClaim(claims, "sub")
	authTime, authTimeOK := numericDateClaim(claims, "auth_time")
	if subject != currentSession.UserID || !authTimeOK || !authTime.Equal(currentSession.AuthTime) {
		return errors.New("id_token_hint does not match the current OP session")
	}

	// RP-Initiated Logout 1.0 §2 recommends accepting an expired ID Token
	// when it identifies a current OP session. Subject and auth_time provide
	// that binding until session identifiers are supported.
	return nil
}

func requiredStringClaim(claims fositejwt.MapClaims, name string) (string, bool) {
	value, ok := claims[name].(string)
	return value, ok && value != ""
}

func (h *Handler) hasRegisteredAudience(ctx context.Context, audiences []string) (bool, error) {
	if h.clientUseCase == nil {
		return false, errors.New("client use case is unavailable")
	}

	for _, audience := range audiences {
		clientID, err := uuid.Parse(audience)
		if err != nil {
			continue
		}

		if _, err := h.clientUseCase.Get(ctx, clientID); err == nil {
			return true, nil
		} else if !errors.Is(err, usecase.ErrClientNotFound) {
			return false, err
		}
	}

	return false, nil
}

func stringListClaim(claims fositejwt.MapClaims, name string) ([]string, bool) {
	value, ok := claims[name]
	if !ok {
		return nil, false
	}

	switch typed := value.(type) {
	case string:
		if typed == "" {
			return nil, false
		}
		return []string{typed}, true
	case []string:
		if len(typed) == 0 || slices.Contains(typed, "") {
			return nil, false
		}
		return typed, true
	case []any:
		values := make([]string, len(typed))
		for index, item := range typed {
			stringValue, ok := item.(string)
			if !ok || stringValue == "" {
				return nil, false
			}
			values[index] = stringValue
		}
		if len(values) == 0 {
			return nil, false
		}
		return values, true
	default:
		return nil, false
	}
}

func numericDateClaim(claims fositejwt.MapClaims, name string) (time.Time, bool) {
	value, ok := claims[name]
	if !ok {
		return time.Time{}, false
	}

	var seconds float64
	switch typed := value.(type) {
	case int64:
		seconds = float64(typed)
	case float64:
		seconds = typed
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return time.Time{}, false
		}
		seconds = parsed
	default:
		return time.Time{}, false
	}
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return time.Time{}, false
	}

	wholeSeconds, fractionalSeconds := math.Modf(seconds)
	return time.Unix(int64(wholeSeconds), int64(fractionalSeconds*float64(time.Second))).UTC(), true
}

func (h *Handler) clearSession(ctx *echo.Context) error {
	session, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to get session")
	}

	session.Values["user_id"] = nil
	session.Values["authenticated"] = false
	session.Options.MaxAge = -1

	if err := session.Save(ctx.Request(), ctx.Response()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save session")
	}
	return nil
}

func sanitizeReturnURL(raw string) string {
	if raw == "" {
		return "/"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host != "" || strings.HasPrefix(raw, "//") {
		return "/"
	}
	return parsed.RequestURI()
}

type authInfo struct {
	UserID   string
	AuthTime time.Time
}

func (h *Handler) getAuthInfo(ctx *echo.Context) (authInfo, bool) {
	session, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return authInfo{}, false
	}

	authenticated, ok := session.Values["authenticated"].(bool)
	if !ok || !authenticated {
		return authInfo{}, false
	}

	userID, ok := session.Values["user_id"].(string)
	if !ok {
		return authInfo{}, false
	}

	authTimeSec, ok := session.Values["auth_time"].(int64)
	if !ok || authTimeSec <= 0 {
		return authInfo{}, false
	}

	return authInfo{UserID: userID, AuthTime: time.Unix(authTimeSec, 0)}, true
}
