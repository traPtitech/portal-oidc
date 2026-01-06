package v1

import (
	"context"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type LoginRequest struct {
	TrapID   string `json:"trap_id" form:"trap_id"`
	Password string `json:"password" form:"password"`
}

func (h *Handler) LoginHandler(c echo.Context) error {
	ctx := c.Request().Context()

	loginSession, err := h.getLoginSessionFromCookie(c)
	if err != nil {
		return err
	}

	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.TrapID == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "trap_id and password are required")
	}

	userID := domain.TrapID(req.TrapID)
	if err := h.verifyCredentials(ctx, userID, req.Password); err != nil {
		return err
	}

	session, err := h.usecase.CreateSession(ctx, userID, c.Request().UserAgent(), c.RealIP())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create session")
	}

	_ = h.usecase.DeleteLoginSession(ctx, loginSession.ID)

	c.SetCookie(&http.Cookie{
		Name:     oidcCookieKeySessionID,
		Value:    uuid.UUID(session.ID).String(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	redirectURL := url.URL{
		Path:     "/oauth2/authorize",
		RawQuery: loginSession.FormData,
	}
	return c.Redirect(http.StatusFound, redirectURL.String())
}

func (h *Handler) getLoginSessionFromCookie(c echo.Context) (domain.LoginSession, error) {
	cookie, err := c.Cookie(loginSessionCookie)
	if err != nil {
		return domain.LoginSession{}, echo.NewHTTPError(http.StatusBadRequest, "login session not found")
	}

	loginSessionID, err := uuid.Parse(cookie.Value)
	if err != nil {
		return domain.LoginSession{}, echo.NewHTTPError(http.StatusBadRequest, "invalid login session")
	}

	loginSession, err := h.usecase.GetLoginSession(c.Request().Context(), domain.LoginSessionID(loginSessionID))
	if err != nil {
		return domain.LoginSession{}, echo.NewHTTPError(http.StatusBadRequest, "login session expired or not found")
	}

	return loginSession, nil
}

func (h *Handler) verifyCredentials(ctx context.Context, userID domain.TrapID, password string) error {
	valid, err := h.usecase.VerifyPassword(ctx, userID, password)
	if err != nil || !valid {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
	}
	return nil
}
