package v1

import (
	"github.com/labstack/echo/v4"
)

func (h *Handler) IntrospectionEndpoint(c echo.Context) error {
	fsess := emptyFositeSession()
	ir, err := h.oauth2.NewIntrospectionRequest(c.Request().Context(), c.Request(), fsess)
	if err != nil {
		h.oauth2.WriteIntrospectionError(c.Request().Context(), c.Response(), err)
		return err
	}

	h.oauth2.WriteIntrospectionResponse(c.Request().Context(), c.Response(), ir)
	return nil
}
