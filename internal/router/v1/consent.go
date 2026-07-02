package v1

import (
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/domain"
)

// GetConsent renders the consent confirmation page for the in-flight authorize
// request encoded in return_url. The page lists the scopes the client is
// requesting and offers approve/deny buttons that submit to PostConsent.
//
// Refs:
//   - OIDC Core 1.0 §3.1.2.4 (Authorization Server Obtains End-User Consent)
//     https://openid.net/specs/openid-connect-core-1_0.html#Consent
func (h *Handler) GetConsent(ctx *echo.Context) error {
	returnURL := sanitizeReturnURL(ctx.QueryParam("return_url"))
	authParams, err := url.ParseRequestURI(returnURL)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid return_url")
	}
	q := authParams.Query()
	clientID := q.Get("client_id")
	scope := q.Get("scope")
	scopes := splitScope(scope)

	clientName := clientID
	if cid, perr := uuid.Parse(clientID); perr == nil && h.clientUseCase != nil {
		if c, gerr := h.clientUseCase.Get(ctx.Request().Context(), cid); gerr == nil {
			clientName = c.Name
		}
	}

	scopeItems := ""
	for _, s := range scopes {
		scopeItems += "<li>" + html.EscapeString(s) + "</li>"
	}

	page := `<!DOCTYPE html>
<html>
<head>
    <title>Authorize</title>
    <style>
        body { font-family: sans-serif; max-width: 480px; margin: 80px auto; padding: 20px; }
        h1 { font-size: 20px; }
        ul { background: #f5f5f5; padding: 12px 32px; border-radius: 6px; }
        form { display: flex; gap: 12px; margin-top: 20px; }
        button { flex: 1; padding: 12px; font-size: 16px; border: none; border-radius: 4px; cursor: pointer; }
        button.allow { background: #007bff; color: white; }
        button.deny { background: #e0e0e0; }
    </style>
</head>
<body>
    <h1>` + html.EscapeString(clientName) + ` is requesting access</h1>
    <p>This application would like to access the following:</p>
    <ul>` + scopeItems + `</ul>
    <form method="POST" action="/oauth2/consent">
        <input type="hidden" name="return_url" value="` + html.EscapeString(returnURL) + `">
        <button class="deny" type="submit" name="action" value="deny">Deny</button>
        <button class="allow" type="submit" name="action" value="allow">Allow</button>
    </form>
</body>
</html>`
	return ctx.HTML(http.StatusOK, page)
}

// PostConsent persists (or revokes) the user's decision and either bounces
// back to the authorize URL or, on denial, sends the access_denied error
// straight to the redirect_uri.
func (h *Handler) PostConsent(ctx *echo.Context) error {
	action := ctx.FormValue("action")
	returnURL := sanitizeReturnURL(ctx.FormValue("return_url"))

	authParams, err := url.ParseRequestURI(returnURL)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid return_url")
	}
	q := authParams.Query()

	if action == "deny" {
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")
		if redirectURI == "" {
			return ctx.HTML(http.StatusForbidden, `<h1>Access denied</h1>`)
		}
		dest, perr := url.Parse(redirectURI)
		if perr != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid redirect_uri")
		}
		dq := dest.Query()
		dq.Set("error", "access_denied")
		dq.Set("error_description", "The user denied the authorization request.")
		if state != "" {
			dq.Set("state", state)
		}
		dest.RawQuery = dq.Encode()
		return ctx.Redirect(http.StatusFound, dest.String())
	}

	info, ok := h.getAuthInfo(ctx)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "not logged in")
	}
	userID, err := uuid.Parse(info.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid session user")
	}
	clientID, err := uuid.Parse(q.Get("client_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid client_id")
	}
	scopes := splitScope(q.Get("scope"))

	if err := h.consents.Upsert(ctx.Request().Context(), domain.UserConsent{
		UserID:   userID,
		ClientID: clientID,
		Scopes:   scopes,
	}); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to record consent")
	}

	return ctx.Redirect(http.StatusFound, returnURL)
}

func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	out := strings.Fields(scope)
	if len(out) == 0 {
		return nil
	}
	return out
}
