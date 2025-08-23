package v1

import (
	"errors"
	"slices"
	"time"

	"github.com/labstack/echo/v4"
)

func (h *Handler) AuthEndpoint(c echo.Context) error {
	ctx := c.Request().Context()
	rw := c.Response().Writer

	ar, err := h.oauth2.NewAuthorizeRequest(ctx, c.Request())
	if err != nil {
		h.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return err
	}

	sessionID, err := extractSessionID(c.Request())
	if err != nil {
		if errors.Is(err, errNoSessionID) {
			return h.serveAuthorizePage(c)
		}
		h.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return err
	}

	session, err := h.usecase.GetSession(ctx, sessionID)
	// セッションがない or 無効の場合は同意画面に飛ばす
	if err != nil {
		return h.serveAuthorizePage(c)
	}

	// 過去に許可されていないスコープがある場合は同意画面に飛ばす
	for _, scope := range ar.GetRequestedScopes() {
		if !slices.Contains(session.AllowedScopes, scope) {
			return h.serveAuthorizePage(c)
		}
	}

	// すべて許可する
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	_, err = h.usecase.CreateSession(ctx, session.UserID, session.ClientID, ar.GetRequestedScopes())
	if err != nil {
		h.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return err
	}

	fsess := newFositeSession(session.ClientID, session.UserID, h.conf.Issuer, time.Now(), time.Now().Add(h.conf.SessionLifespan), session.CreatedAt)

	// レスポンスを作成
	response, err := h.oauth2.NewAuthorizeResponse(ctx, ar, fsess)

	if err != nil {
		h.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return err
	}

	h.oauth2.WriteAuthorizeResponse(ctx, rw, ar, response)
	return nil
}
