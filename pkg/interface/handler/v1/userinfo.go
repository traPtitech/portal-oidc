package v1

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

// NOTE: エラーレスポンスの書き込みはEchoではなくfosite側で行うので、e.JSONなどで書き込まない
func (h *Handler) UserInfoEndpoint(c echo.Context) error {
	ctx := c.Request().Context()

	sess := &openid.DefaultSession{}

	tt, ar, err := h.oauth2.IntrospectToken(ctx, fosite.AccessTokenFromRequest(c.Request()), fosite.AccessToken, sess)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, c.Response().Writer, ar, err)
		return err
	}

	if tt != fosite.AccessToken {
		h.oauth2.WriteAccessError(ctx, c.Response().Writer, ar, fosite.ErrRequestUnauthorized)
		return err
	}

	claims := sess.IDTokenClaims()
	sub := domain.TrapID(claims.Subject)
	ui, err := h.usecase.GetUserInfo(ctx, sub)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, c.Response().Writer, ar, err)
		return err
	}

	err = c.JSON(http.StatusOK, ui)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, c.Response().Writer, ar, err)
		return err
	}

	return nil
}
