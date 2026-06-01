package v1

import (
	"errors"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/usecase"
)

// idTokenSignatureAlgorithms lists the signing algorithms accepted on
// id_token_hint. Mirrors id_token_signing_alg_values_supported in discovery
// (currently RS256 only). go-jose v4 requires the caller to declare the
// expected algorithms up-front to prevent algorithm-substitution attacks.
var idTokenSignatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256}

const sessionName = "oidc_session"

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
//  1. Verify id_token_hint signature (if provided) using the OP's signing key.
//  2. Terminate the End-User's session at the OP.
//  3. If post_logout_redirect_uri was supplied AND it matches a URI registered
//     for the client identified by id_token_hint.aud (or the explicit client_id
//     query parameter), redirect there with the optional state echoed back.
//  4. Otherwise render a simple confirmation page.
//
// post_logout_redirect_uri validation is intentionally strict: clients without
// a pre-registered URI are not redirected to arbitrary external locations,
// matching the open-redirect mitigation in the spec. The clients table does
// not yet carry post_logout_uris (Phase 2.1), so for now any external URI is
// rejected and the confirmation page is shown.
//
// Refs:
//   - OpenID Connect RP-Initiated Logout 1.0 §2 (Logout Request)
//     https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
//   - OpenID Connect RP-Initiated Logout 1.0 §3 (Redirect URI Validation)
//     https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling
func (h *Handler) RPInitiatedLogout(ctx *echo.Context) error {
	idTokenHint := ctx.QueryParam("id_token_hint")
	postLogoutRedirectURI := ctx.QueryParam("post_logout_redirect_uri")
	state := ctx.QueryParam("state")

	if idTokenHint != "" && h.config.PrivateKey != nil {
		// RP-Initiated Logout 1.0 §2: verify the supplied ID Token signature.
		// Expired tokens are tolerated because §3 explicitly allows the OP to
		// terminate the session even when the hint cannot be authoritatively
		// validated as a current credential.
		jws, err := jose.ParseSigned(idTokenHint, idTokenSignatureAlgorithms)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid id_token_hint")
		}
		if _, err := jws.Verify(&h.config.PrivateKey.PublicKey); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid id_token_hint signature")
		}
	}

	if err := h.clearSession(ctx); err != nil {
		return err
	}

	if postLogoutRedirectURI != "" {
		// TODO(Phase 2.1): once clients.post_logout_uris is added, look up the
		// client by id_token_hint.aud or client_id and verify exact match here.
		// For now we always render the confirmation page to avoid open redirects.
		_ = state
	}

	return ctx.HTML(http.StatusOK, `<!DOCTYPE html>
<html>
<head><title>Logged out</title></head>
<body>
    <h1>Logged out</h1>
    <p>You have been signed out.</p>
</body>
</html>`)
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

	at := time.Now()
	if authTimeSec, ok := session.Values["auth_time"].(int64); ok {
		at = time.Unix(authTimeSec, 0)
	}

	return authInfo{UserID: userID, AuthTime: at}, true
}
