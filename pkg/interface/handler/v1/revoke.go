package v1

import "github.com/labstack/echo/v4"

func (h *Handler) RevokeEndpoint(c echo.Context) error {
	err := h.oauth2.NewRevocationRequest(c.Request().Context(), c.Request())

	h.oauth2.WriteRevocationResponse(c.Request().Context(), c.Response(), err)
	return nil
}
