package v1

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/traPtitech/portal-oidc/internal/domain"
	models "github.com/traPtitech/portal-oidc/internal/interface/handler/v1/gen"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

func clientToResponse(c domain.Client, secret *string) models.Client {
	return models.Client{
		Id:           c.ID.UUID(),
		Secret:       secret,
		Type:         models.ClientType(c.Type.String()),
		Name:         c.Name,
		RedirectUris: c.RedirectURIs,
	}
}

func (h *Handler) CreateClientHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req models.CreateClientRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	ctype, err := domain.ParseClientType(string(req.Type))
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	_, ok := ctx.Value(domain.ContextKeyUser).(domain.TrapID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, "unauthorized")
	}

	result, err := h.usecase.CreateClient(ctx, usecase.CreateClientParams{
		Name:         req.Name,
		Type:         ctype,
		RedirectURIs: req.RedirectUris,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	var secret *string
	if result.RawSecret != "" {
		secret = &result.RawSecret
	}

	return c.JSON(http.StatusCreated, clientToResponse(result.Client, secret))
}

func (h *Handler) ListClientsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	clients, err := h.usecase.ListClients(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	res := make([]models.Client, len(clients))
	for i, cl := range clients {
		res[i] = clientToResponse(cl, nil)
	}

	return c.JSON(http.StatusOK, res)
}

func (h *Handler) UpdateClientHandler(c echo.Context) error {
	ctx := c.Request().Context()

	var req models.UpdateClientRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	ctype, err := domain.ParseClientType(string(req.Type))
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	id, err := uuid.Parse(c.Param("clientId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	client, err := h.usecase.UpdateClient(ctx, domain.ClientID(id), usecase.UpdateClientParams{
		Name:         req.Name,
		Type:         ctype,
		RedirectURIs: req.RedirectUris,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	return c.JSON(http.StatusOK, clientToResponse(client, nil))
}

func (h *Handler) UpdateClientSecretHandler(c echo.Context) error {
	ctx := c.Request().Context()

	id, err := uuid.Parse(c.Param("clientId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	result, err := h.usecase.UpdateClientSecret(ctx, domain.ClientID(id))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	return c.JSON(http.StatusOK, models.UpdateClientSecretResponse{
		ClientSecret: result.RawSecret,
	})
}

func (h *Handler) DeleteClientHandler(c echo.Context) error {
	ctx := c.Request().Context()

	clientId := c.Param(paramKeyClientId)
	if clientId == "" {
		return c.JSON(http.StatusBadRequest, "clientId is required")
	}

	id, err := uuid.Parse(clientId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	err = h.usecase.DeleteClient(ctx, domain.ClientID(id))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	return c.NoContent(http.StatusNoContent)
}
