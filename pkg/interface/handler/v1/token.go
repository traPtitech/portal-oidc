package v1

import (
	"github.com/labstack/echo/v4"
)

func (h *Handler) TokenEndpoint(c echo.Context) error {
	ctx := c.Request().Context()
	rw := c.Response().Writer

	fsess := emptyFositeSession()

	ar, err := h.oauth2.NewAccessRequest(ctx, c.Request(), fsess)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, rw, ar, err)
		return nil // fosite がレスポンスを書いたので nil を返す
	}

	// Client Credentials Flow の場合はすべて許可する
	if ar.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}
	}

	response, err := h.oauth2.NewAccessResponse(ctx, ar)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, rw, ar, err)
		return nil
	}

	h.oauth2.WriteAccessResponse(ctx, rw, ar, response)
	return nil
}
