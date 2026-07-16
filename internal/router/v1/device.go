package v1

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oauth"
)

const (
	deviceCodeBytes        = 32
	userCodeChars          = "BCDFGHJKLMNPQRSTVWXZ" // exclude vowels and 0/1/I/O for human entry
	userCodeLength         = 8
	deviceAuthorizationTTL = 10 * time.Minute
	devicePollInterval     = 5
)

// DeviceAuthorize implements RFC 8628 §3.1 (Device Authorization Request).
// The device POSTs client_id (and optional scope) and receives a device_code
// it polls with, plus a user_code the human types into a browser.
//
// Refs:
//   - RFC 8628 §3.1 (Device Authorization Request)
//     https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
//   - RFC 8628 §3.2 (Device Authorization Response)
//     https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
func (h *Handler) DeviceAuthorize(ctx *echo.Context) error {
	clientID := ctx.FormValue("client_id")
	scope := ctx.FormValue("scope")
	if clientID == "" {
		return ctx.JSON(http.StatusBadRequest, oauthErrorJSON("invalid_request", "client_id is required"))
	}
	cid, err := uuid.Parse(clientID)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, oauthErrorJSON("invalid_client", "client_id must be a UUID"))
	}
	if _, err := h.clientUseCase.Get(ctx.Request().Context(), cid); err != nil {
		return ctx.JSON(http.StatusUnauthorized, oauthErrorJSON("invalid_client", "unknown client"))
	}

	deviceCode, err := randomDeviceCode()
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, oauthErrorJSON("server_error", err.Error()))
	}
	userCode, err := randomUserCode()
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, oauthErrorJSON("server_error", err.Error()))
	}

	expires := time.Now().Add(deviceAuthorizationTTL)
	auth := domain.DeviceAuthorization{
		DeviceCode:   deviceCode,
		UserCode:     userCode,
		ClientID:     cid,
		Scopes:       splitScopeField(scope),
		Status:       domain.DeviceAuthorizationStatusPending,
		ExpiresAt:    expires,
		PollInterval: devicePollInterval,
	}
	if err := h.deviceAuths.Create(ctx.Request().Context(), auth); err != nil {
		return ctx.JSON(http.StatusInternalServerError, oauthErrorJSON("server_error", err.Error()))
	}

	issuer := strings.TrimRight(h.config.Issuer, "/")
	return ctx.JSON(http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          issuer + "/oauth2/device",
		"verification_uri_complete": issuer + "/oauth2/device?user_code=" + userCode,
		"expires_in":                int(deviceAuthorizationTTL.Seconds()),
		"interval":                  devicePollInterval,
	})
}

// GetDeviceVerification renders the user-facing form where the human enters
// the user_code displayed by the device. The user_code may also arrive
// pre-filled via the verification_uri_complete query parameter.
func (h *Handler) GetDeviceVerification(ctx *echo.Context) error {
	prefill := ctx.QueryParam("user_code")
	page := `<!DOCTYPE html>
<html>
<head>
    <title>Device Authorization</title>
    <style>
        body { font-family: sans-serif; max-width: 420px; margin: 100px auto; padding: 20px; }
        input { padding: 10px; font-size: 18px; text-transform: uppercase; letter-spacing: 4px; width: 100%; box-sizing: border-box; }
        button { padding: 12px; font-size: 16px; background: #007bff; color: white; border: none; cursor: pointer; width: 100%; margin-top: 12px; }
    </style>
</head>
<body>
    <h1>Authorize Device</h1>
    <p>Enter the code shown on your device:</p>
    <form method="POST" action="/oauth2/device">
        <input type="text" name="user_code" placeholder="ABCD-EFGH" required autofocus value="` + html.EscapeString(prefill) + `">
        <button type="submit">Continue</button>
    </form>
</body>
</html>`
	return ctx.HTML(http.StatusOK, page)
}

// PostDeviceVerification processes the user's submission of a user_code,
// requires login, then either displays a consent form or, on a follow-up
// "approve" submission, marks the authorization as approved.
func (h *Handler) PostDeviceVerification(ctx *echo.Context) error {
	userCode := strings.ToUpper(strings.TrimSpace(ctx.FormValue("user_code")))
	action := ctx.FormValue("action")
	if userCode == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "user_code required")
	}

	auth, err := h.deviceAuths.GetByUserCode(ctx.Request().Context(), userCode)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceAuthorizationNotFound) {
			return ctx.HTML(http.StatusNotFound, `<h1>Invalid code</h1>`)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	if auth.IsExpired(time.Now()) || auth.Status != domain.DeviceAuthorizationStatusPending {
		return ctx.HTML(http.StatusGone, `<h1>This code is no longer valid</h1>`)
	}

	info, ok := h.getAuthInfo(ctx)
	if !ok {
		// Bounce through /login carrying the user_code so the verification
		// form is pre-filled when we come back.
		return ctx.Redirect(http.StatusFound, "/login?return_url="+
			"%2Foauth2%2Fdevice%3Fuser_code%3D"+userCode)
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid session subject")
	}

	switch action {
	case "approve":
		if err := h.deviceAuths.Approve(ctx.Request().Context(), auth.ID, userID); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		return ctx.HTML(http.StatusOK, `<h1>Device authorized</h1><p>You may close this window.</p>`)
	case "deny":
		if err := h.deviceAuths.Deny(ctx.Request().Context(), auth.ID); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		return ctx.HTML(http.StatusOK, `<h1>Authorization denied</h1>`)
	}

	// Show consent form.
	scopeList := ""
	for _, s := range auth.Scopes {
		scopeList += "<li>" + html.EscapeString(s) + "</li>"
	}
	if scopeList == "" {
		scopeList = "<li>(no scopes requested)</li>"
	}
	page := `<!DOCTYPE html>
<html>
<head><title>Authorize Device</title></head>
<body style="font-family: sans-serif; max-width: 420px; margin: 80px auto;">
    <h1>Authorize this device?</h1>
    <p>The device requesting access wants:</p>
    <ul>` + scopeList + `</ul>
    <form method="POST" action="/oauth2/device">
        <input type="hidden" name="user_code" value="` + html.EscapeString(userCode) + `">
        <button type="submit" name="action" value="deny">Deny</button>
        <button type="submit" name="action" value="approve">Allow</button>
    </form>
</body>
</html>`
	return ctx.HTML(http.StatusOK, page)
}

// DeviceTokenGrant handles grant_type=urn:ietf:params:oauth:grant-type:device_code
// at the token endpoint. RFC 8628 §3.5 specifies the polling response codes:
// authorization_pending while the user has not finished the ceremony,
// access_denied if they refused, expired_token after the TTL, slow_down to
// throttle aggressive pollers (we approximate by enforcing the stored
// interval), and a normal token response on success.
//
// Refs:
//   - RFC 8628 §3.4 (Device Access Token Request)
//     https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
//   - RFC 8628 §3.5 (Device Access Token Response)
//     https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
func (h *Handler) DeviceTokenGrant(ctx *echo.Context) error {
	deviceCode := ctx.FormValue("device_code")
	if deviceCode == "" {
		return ctx.JSON(http.StatusBadRequest, oauthErrorJSON("invalid_request", "device_code is required"))
	}

	auth, err := h.deviceAuths.GetByDeviceCode(ctx.Request().Context(), deviceCode)
	if err != nil {
		if errors.Is(err, repository.ErrDeviceAuthorizationNotFound) {
			return ctx.JSON(http.StatusBadRequest, oauthErrorJSON("invalid_grant", "unknown device_code"))
		}
		return ctx.JSON(http.StatusInternalServerError, oauthErrorJSON("server_error", err.Error()))
	}

	if auth.IsExpired(time.Now()) {
		return ctx.JSON(http.StatusBadRequest, oauthErrorJSON("expired_token", "device_code has expired"))
	}
	if auth.LastPolledAt != nil && time.Since(*auth.LastPolledAt) < time.Duration(auth.PollInterval)*time.Second {
		return ctx.JSON(http.StatusBadRequest, oauthErrorJSON("slow_down", "polling too quickly"))
	}
	if err := h.deviceAuths.Touch(ctx.Request().Context(), deviceCode); err != nil {
		// Best-effort throttle bookkeeping — proceed even on failure.
		_ = err
	}

	switch auth.Status {
	case domain.DeviceAuthorizationStatusPending:
		return ctx.JSON(http.StatusBadRequest, oauthErrorJSON("authorization_pending", "user has not yet completed authorization"))
	case domain.DeviceAuthorizationStatusDenied:
		return ctx.JSON(http.StatusBadRequest, oauthErrorJSON("access_denied", "the user denied the request"))
	case domain.DeviceAuthorizationStatusExpired:
		return ctx.JSON(http.StatusBadRequest, oauthErrorJSON("expired_token", "device_code has expired"))
	case domain.DeviceAuthorizationStatusAuthorized:
		// fall through
	default:
		return ctx.JSON(http.StatusInternalServerError, oauthErrorJSON("server_error", "unknown status"))
	}

	if auth.UserID == nil {
		return ctx.JSON(http.StatusInternalServerError, oauthErrorJSON("server_error", "authorized device without user"))
	}

	resp, err := h.issueDeviceTokens(ctx, auth)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, oauthErrorJSON("server_error", err.Error()))
	}
	return ctx.JSON(http.StatusOK, resp)
}

// issueDeviceTokens mints fosite-compatible HMAC tokens via the shared
// strategy so /userinfo and /introspect can validate them like any other
// access token. The persisted JTI / token_hash are the signature halves of
// the HMAC tokens, matching how the regular grants store them.
func (h *Handler) issueDeviceTokens(ctx *echo.Context, auth domain.DeviceAuthorization) (map[string]any, error) {
	c := ctx.Request().Context()
	requestID := uuid.New().String()

	requester := &fosite.Request{
		ID:          requestID,
		RequestedAt: time.Now(),
		Client: &oauth.Client{
			ID:           auth.ClientID.String(),
			RedirectURIs: []string{},
			GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:device_code"},
		},
		Session: oauth.NewSession(auth.UserID.String(), time.Now()),
	}
	requester.SetRequestedScopes(auth.Scopes)
	for _, s := range auth.Scopes {
		requester.GrantScope(s)
	}

	accessToken, accessSig, err := h.tokenStrategy.GenerateAccessToken(c, requester)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	accessExpires := now.Add(time.Hour) // matches default lifespan; follow-up: pull from config

	if err := h.tokens.Create(c, domain.Token{
		ID:          uuid.New(),
		RequestID:   requestID,
		ClientID:    auth.ClientID,
		UserID:      *auth.UserID,
		AccessToken: accessSig,
		Scopes:      auth.Scopes,
		ExpiresAt:   accessExpires,
	}); err != nil {
		return nil, err
	}

	// RFC 8628 §3.5: refresh_token is OPTIONAL in the device access token
	// response. The combined tokens table on main has a UNIQUE access_token
	// constraint that breaks two refresh-only rows; emitting a refresh token
	// here is deferred until the access_tokens / refresh_tokens split lands.
	return map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(accessExpires).Seconds()),
		"scope":        strings.Join(auth.Scopes, " "),
	}, nil
}

func randomDeviceCode() (string, error) {
	buf := make([]byte, deviceCodeBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomUserCode() (string, error) {
	// User codes are read aloud and typed; restrict the alphabet to
	// unambiguous characters and split with a hyphen for legibility.
	out := make([]byte, userCodeLength)
	for i := range out {
		idx, err := randomIndex(len(userCodeChars))
		if err != nil {
			return "", err
		}
		out[i] = userCodeChars[idx]
	}
	mid := userCodeLength / 2
	return string(out[:mid]) + "-" + string(out[mid:]), nil
}

func randomIndex(n int) (int, error) {
	buf := make([]byte, 1)
	if _, err := rand.Read(buf); err != nil {
		return 0, err
	}
	return int(buf[0]) % n, nil
}

func splitScopeField(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func oauthErrorJSON(code, description string) map[string]any {
	out := map[string]any{"error": code}
	if description != "" {
		out["error_description"] = description
	}
	return out
}
