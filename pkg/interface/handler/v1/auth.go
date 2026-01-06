package v1

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/usecase"
)

const loginSessionCookie = "login_session"

// requireLogin は未認証ユーザーをログイン画面にリダイレクトする
func (h *Handler) requireLogin(c echo.Context, clientID, redirectURI, forms string, scopes []string) error {
	ctx := c.Request().Context()

	// ログインセッションを作成 (元のリクエストパラメータを保存)
	loginSession, err := h.usecase.CreateLoginSession(ctx, clientID, redirectURI, forms, scopes)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create login session")
	}

	// ログインセッションIDをCookieにセット
	c.SetCookie(&http.Cookie{
		Name:     loginSessionCookie,
		Value:    uuid.UUID(loginSession.ID).String(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return c.Redirect(http.StatusFound, "/login")
}

func (h *Handler) AuthEndpoint(c echo.Context) error {
	ctx := c.Request().Context()
	rw := c.Response().Writer

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

	// セッション検証
	session, err := h.validateSession(c, ar, clientIDStr)
	if err != nil {
		if errors.Is(err, errAuthHandled) {
			return nil
		}
		return err
	}

	// 同意検証
	if redirect := h.checkConsent(c, ar, session.UserID, clientID); redirect != nil {
		return redirect
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

var errAuthHandled = errors.New("auth error already handled")

func (h *Handler) validateSession(c echo.Context, ar fosite.AuthorizeRequester, clientIDStr string) (*domain.Session, error) {
	ctx := c.Request().Context()
	redirectURI := ar.GetRedirectURI().String()
	scopes := ar.GetRequestedScopes()
	forms := c.Request().URL.RawQuery

	sessionID, err := extractSessionID(c.Request())
	if err != nil {
		if errors.Is(err, errNoSessionID) {
			if err := h.requireLogin(c, clientIDStr, redirectURI, forms, scopes); err != nil {
				return nil, err
			}
			return nil, errAuthHandled
		}
		h.oauth2.WriteAuthorizeError(ctx, c.Response().Writer, ar, err)
		return nil, errAuthHandled
	}

	session, err := h.usecase.GetSession(ctx, sessionID)
	if err != nil {
		if err := h.requireLogin(c, clientIDStr, redirectURI, forms, scopes); err != nil {
			return nil, err
		}
		return nil, errAuthHandled
	}

	return &session, nil
}

func (h *Handler) checkConsent(c echo.Context, ar fosite.AuthorizeRequester, userID domain.TrapID, clientID domain.ClientID) error {
	ctx := c.Request().Context()

	consent, err := h.usecase.GetUserConsent(ctx, userID, clientID)
	if err != nil {
		if errors.Is(err, usecase.ErrConsentNotFound) {
			return c.Redirect(http.StatusFound, "/oauth2/consent")
		}
		h.oauth2.WriteAuthorizeError(ctx, c.Response().Writer, ar, err)
		return nil
	}

	for _, scope := range ar.GetRequestedScopes() {
		if !slices.Contains(consent.Scopes, scope) {
			return c.Redirect(http.StatusFound, "/oauth2/consent")
		}
	}

	return nil
}
