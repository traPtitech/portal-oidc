package v1

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

const authRequestCookie = "auth_request"

func (h *Handler) AuthEndpoint(c echo.Context) error {
	ctx := c.Request().Context()
	rw := c.Response().Writer

	// fosite がリクエストを検証 (client_id, redirect_uri 等)
	ar, err := h.oauth2.NewAuthorizeRequest(ctx, c.Request())
	if err != nil {
		h.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return nil
	}

	clientIDStr := ar.GetClient().GetID()
	clientUUID, err := uuid.Parse(clientIDStr)
	if err != nil {
		h.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return nil
	}
	clientID := domain.ClientID(clientUUID)

	// セッション確認
	session, err := h.getAuthenticatedSession(c)
	if err != nil {
		// 未認証 → ログインへリダイレクト (検証済みリクエストを保存)
		form := ar.GetRequestForm()
		return h.redirectToLogin(c, domain.AuthorizationRequest{
			ClientID:            clientIDStr,
			RedirectURI:         form.Get("redirect_uri"),
			Scope:               form.Get("scope"),
			State:               form.Get("state"),
			CodeChallenge:       form.Get("code_challenge"),
			CodeChallengeMethod: form.Get("code_challenge_method"),
		})
	}

	// スコープを許可
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	fsess := newFositeSession(clientID, session.UserID, h.conf.Issuer, time.Now(), time.Now().Add(h.conf.SessionLifespan), session.AuthTime)

	response, err := h.oauth2.NewAuthorizeResponse(ctx, ar, fsess)
	if err != nil {
		h.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return nil
	}

	h.oauth2.WriteAuthorizeResponse(ctx, rw, ar, response)
	return nil
}

var errNoSession = errors.New("no authenticated session")

func (h *Handler) getAuthenticatedSession(c echo.Context) (*domain.Session, error) {
	sessionID, err := extractSessionID(c.Request())
	if err != nil {
		return nil, errNoSession
	}

	session, err := h.usecase.GetSession(c.Request().Context(), sessionID)
	if err != nil {
		return nil, errNoSession
	}

	return &session, nil
}

func (h *Handler) redirectToLogin(c echo.Context, req domain.AuthorizationRequest) error {
	ctx := c.Request().Context()

	// AuthorizationRequest作成 (fosite検証済みのリクエストを保存)
	authReq, err := h.usecase.CreateAuthorizationRequest(ctx, req)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create authorization request")
	}

	c.SetCookie(&http.Cookie{
		Name:     authRequestCookie,
		Value:    uuid.UUID(authReq.ID).String(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return c.Redirect(http.StatusFound, "/login")
}
