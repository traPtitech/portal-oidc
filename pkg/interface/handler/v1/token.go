package v1

import (
	"github.com/labstack/echo/v4"
	"github.com/ory/fosite/handler/openid"
)

func (h *Handler) TokenEndpoint(c echo.Context) error {
	ctx := c.Request().Context()
	rw := c.Response().Writer
	req := c.Request()

	session := &openid.DefaultSession{}

	accessRequest, err := h.oauth2.NewAccessRequest(ctx, req, session)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, rw, accessRequest, err)
		return nil
	}

	// Grant requested scopes
	for _, scope := range accessRequest.GetRequestedScopes() {
		accessRequest.GrantScope(scope)
	}

	response, err := h.oauth2.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		h.oauth2.WriteAccessError(ctx, rw, accessRequest, err)
		return nil
	}

	h.oauth2.WriteAccessResponse(ctx, rw, accessRequest, response)
	return nil
}
