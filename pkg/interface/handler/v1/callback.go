package v1

import (
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

func (h *Handler) CallbackEndpoint(c echo.Context) error {
	// セッション情報取得
	// セッションからAutorizationEndpointのパラメータを復元
	// そこからは処理同一、ただしスコープ足りなくても同意画面飛ばさない

	ctx := c.Request().Context()
	rw := c.Response().Writer

	sessionID, err := uuid.Parse(c.QueryParam(paramKeySessionId))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid Session")
	}

	session, err := h.usecase.GetLoginSession(ctx, domain.LoginSessionID(sessionID))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid Session")
	}

	values, err := url.ParseQuery(session.Forms)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid Session")
	}

	c.Request().Form = values

	ar, err := h.oauth2.NewAuthorizeRequest(ctx, c.Request())
	if err != nil {
		h.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return err
	}

	// 許可されたスコープのみ飛ばす
	for _, scope := range ar.GetRequestedScopes() {
		if slices.Contains(session.AllowedScopes, scope) {
			ar.GrantScope(scope)
		}
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
