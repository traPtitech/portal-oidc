package v1

import (
	"github.com/labstack/echo/v4"
)

func (h *Handler) TokenEndpoint(c echo.Context) error {
	ctx := c.Request().Context()

	fsess := emptyFositeSession()

	ar, err := h.oauth2.NewAccessRequest(ctx, c.Request(), fsess)

	if err != nil {
		h.oauth2.WriteAccessError(ctx, c.Response().Writer, ar, err)
		return err
	}

	// Client Credentials Flow の場合はすべて許可する
	if ar.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}
	}

	response, err := h.oauth2.NewAccessResponse(ctx, ar)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, c.Response().Writer, ar, err)
		return err
	}

	h.oauth2.WriteAccessResponse(ctx, c.Response().Writer, ar, response)

	return nil
}
