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

	authReq, err := h.getAuthorizationRequestFromCookie(c)
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

	_ = h.usecase.DeleteAuthorizationRequest(ctx, authReq.ID)

	c.SetCookie(&http.Cookie{
		Name:     oidcCookieKeySessionID,
		Value:    uuid.UUID(session.ID).String(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// 認可フローに戻る
	redirectURL := url.URL{
		Path: "/oauth2/authorize",
		RawQuery: url.Values{
			"client_id":             {authReq.ClientID},
			"redirect_uri":          {authReq.RedirectURI},
			"scope":                 {authReq.Scope},
			"state":                 {authReq.State},
			"response_type":         {"code"},
			"code_challenge":        {authReq.CodeChallenge},
			"code_challenge_method": {authReq.CodeChallengeMethod},
		}.Encode(),
	}
	return c.Redirect(http.StatusFound, redirectURL.String())
}

func (h *Handler) getAuthorizationRequestFromCookie(c echo.Context) (domain.AuthorizationRequest, error) {
	cookie, err := c.Cookie(authRequestCookie)
	if err != nil {
		return domain.AuthorizationRequest{}, echo.NewHTTPError(http.StatusBadRequest, "authorization request not found")
	}

	authReqID, err := uuid.Parse(cookie.Value)
	if err != nil {
		return domain.AuthorizationRequest{}, echo.NewHTTPError(http.StatusBadRequest, "invalid authorization request")
	}

	authReq, err := h.usecase.GetAuthorizationRequest(c.Request().Context(), domain.AuthorizationRequestID(authReqID))
	if err != nil {
		return domain.AuthorizationRequest{}, echo.NewHTTPError(http.StatusBadRequest, "authorization request expired or not found")
	}

	return authReq, nil
}

func (h *Handler) verifyCredentials(ctx context.Context, userID domain.TrapID, password string) error {
	valid, err := h.usecase.VerifyPassword(ctx, userID, password)
	if err != nil || !valid {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
	}
	return nil
}
