package v1

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

//go:embed loginassets/*
var loginAssets embed.FS
var loginTemplate = template.Must(template.ParseFS(loginAssets, "loginassets/login.html"))

func (h *Handler) RegisterLoginAssets(e *echo.Echo) {
	files, err := fs.Sub(loginAssets, "loginassets")
	if err != nil {
		panic(err)
	}
	e.GET("/login/assets/*", echo.WrapHandler(http.StripPrefix("/login/assets/", http.FileServer(http.FS(files)))))
}
func setLoginHeaders(c *echo.Context) {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
}
func (h *Handler) GetLogin(c *echo.Context) error {
	setLoginHeaders(c)
	session, err := h.sessions.Get(c.Request(), sessionName)
	if err != nil {
		session.Values = make(map[interface{}]interface{})
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return echo.NewHTTPError(500, "login unavailable")
	}
	csrf := base64.RawURLEncoding.EncodeToString(token)
	session.Values["login_csrf"] = csrf
	if err := session.Save(c.Request(), c.Response()); err != nil {
		return echo.NewHTTPError(500, "login unavailable")
	}
	policy, err := json.Marshal(domain.CurrentKDFPolicy())
	if err != nil {
		return echo.NewHTTPError(500, "login unavailable")
	}
	var b bytes.Buffer
	if err := loginTemplate.Execute(&b, map[string]string{"ReturnURL": sanitizeReturnURL(c.QueryParam("return_url")), "CSRF": csrf, "Policy": string(policy)}); err != nil {
		return echo.NewHTTPError(500, "login unavailable")
	}
	return c.HTML(200, b.String())
}
func (h *Handler) PostLogin(c *echo.Context) error {
	setLoginHeaders(c)
	session, err := h.sessions.Get(c.Request(), sessionName)
	if err != nil {
		return c.NoContent(403)
	}
	csrf, ok := session.Values["login_csrf"].(string)
	if !ok || csrf == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(c.FormValue("csrf_token"))) != 1 {
		return c.NoContent(403)
	}
	if c.Request().Form.Has("password") {
		return c.NoContent(400)
	}
	if h.userUseCase == nil {
		return c.NoContent(503)
	}
	user, err := h.userUseCase.Authenticate(c.Request().Context(), c.FormValue("email"), c.FormValue("auth_secret"))
	if err != nil {
		if errors.Is(err, usecase.ErrInvalidPassword) || errors.Is(err, usecase.ErrUserNotFound) || errors.Is(err, usecase.ErrUserNotActive) {
			retry := "/login?return_url=" + url.QueryEscape(sanitizeReturnURL(c.FormValue("return_url")))
			return c.HTML(401, `<h1>Login failed</h1><p>Invalid credentials.</p><a href="`+html.EscapeString(retry)+`">Try again</a>`)
		}
		return c.NoContent(503)
	}
	session.Values["user_id"] = user.ID.String()
	session.Values["authenticated"] = true
	session.Values["auth_time"] = time.Now().Unix()
	delete(session.Values, "login_csrf")
	clearLogoutConfirmation(session)
	if err := session.Save(c.Request(), c.Response()); err != nil {
		return c.NoContent(500)
	}
	return c.Redirect(302, sanitizeReturnURL(c.FormValue("return_url")))
}
