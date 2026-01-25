package v1

import (
	"errors"
	"html"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/traPtitech/portal-oidc/internal/repository"
)

const sessionName = "oidc_session"

func (h *Handler) GetLogin(ctx echo.Context) error {
	returnURL := ctx.QueryParam("return_url")
	if returnURL == "" {
		returnURL = "/"
	}

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

func (h *Handler) PostLogin(ctx echo.Context) error {
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

	if err := session.Save(ctx.Request(), ctx.Response()); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save session")
	}

	if returnURL == "" {
		returnURL = "/"
	}
	return ctx.Redirect(http.StatusFound, returnURL)
}

func (h *Handler) authenticateTestUser(username, password string) (string, error) {
	if username == "testuser" && password == "password" {
		return h.config.TestUserID, nil
	}
	return "", errors.New("invalid credentials")
}

func (h *Handler) authenticatePortalUser(ctx echo.Context, trapID, password string) (string, error) {
	user, err := h.userRepo.Authenticate(ctx.Request().Context(), trapID, password)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) ||
			errors.Is(err, repository.ErrInvalidPassword) ||
			errors.Is(err, repository.ErrUserNotActive) {
			return "", errors.New("authentication failed")
		}
		return "", err
	}

	return user.ID, nil
}

func (h *Handler) Logout(ctx echo.Context) error {
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

	return ctx.Redirect(http.StatusFound, "/")
}

func (h *Handler) getAuthenticatedUser(ctx echo.Context) string {
	session, err := h.sessions.Get(ctx.Request(), sessionName)
	if err != nil {
		return ""
	}

	authenticated, ok := session.Values["authenticated"].(bool)
	if !ok || !authenticated {
		return ""
	}

	userID, ok := session.Values["user_id"].(string)
	if !ok {
		return ""
	}

	return userID
}
