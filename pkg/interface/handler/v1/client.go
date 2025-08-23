package v1

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	models "github.com/traPtitech/portal-oidc/pkg/interface/handler/v1/gen"
)

func (h *Handler) CreateClientHandler(c echo.Context) error {

	ctx := c.Request().Context()

	req := models.CreateClientRequest{}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	ctype, err := domain.ParseClientType(req.ClientType)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	userID, ok := ctx.Value(domain.ContextKeyUser).(domain.TrapID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, "unauthorized")
	}

	client, err := h.usecase.CreateClient(ctx, userID, ctype, req.ClientName, req.Description, req.RedirectUris)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	res := createClientResponse{
		ClientID:     client.ID.String(),
		Typ:          client.Type.String(),
		Name:         client.Name,
		Description:  client.Description,
		RedirectURIs: client.RedirectURIs,
		Secret:       client.Secret,
		Expires:      0, // Never
	}

	return c.JSON(http.StatusCreated, res)
}

func (h *Handler) ListClientsHandler(c echo.Context) error {
	ctx := c.Request().Context()

	userID, ok := ctx.Value(domain.ContextKeyUser).(domain.TrapID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, "unauthorized")
	}

	clients, err := h.usecase.ListClientsByUser(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	res := make([]models.Client, len(clients))
	for i, c := range clients {
		res[i] = models.Client{
			ClientId:     c.ID.String(),
			ClientType:   c.Type.String(),
			ClientName:   c.Name,
			Description:  c.Description,
			RedirectUris: c.RedirectURIs,
		}
	}

	return c.JSON(http.StatusOK, res)
}

func (h *Handler) UpdateClientHandler(c echo.Context) error {
	ctx := c.Request().Context()

	req := models.UpdateClientRequest{}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	ctype, err := domain.ParseClientType(req.ClientType)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	userID, ok := ctx.Value(domain.ContextKeyUser).(domain.TrapID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, "unauthorized")
	}

	id, err := uuid.Parse(c.Param("clientId"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	client, err := h.usecase.UpdateClient(ctx, domain.ClientID(id), userID, ctype, req.ClientName, req.Description, req.RedirectUris)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	res := models.Client{
		ClientId:     client.ID.String(),
		ClientType:   client.Type.String(),
		ClientName:   client.Name,
		Description:  client.Description,
		RedirectUris: client.RedirectURIs,
	}

	return c.JSON(http.StatusOK, res)
}

func (h *Handler) UpdateClientSecretHandler(c echo.Context) error {
	ctx := c.Request().Context()

	req := models.UpdateClientSecretRequest{}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	userID, ok := ctx.Value(domain.ContextKeyUser).(domain.TrapID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, "unauthorized")
	}

	id, err := uuid.Parse(req.ClientId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	client, err := h.usecase.UpdateClientSecret(ctx, userID, domain.ClientID(id))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	res := models.UpdateClientSecretResponse{
		ClientSecret: client.Secret,
	}

	return c.JSON(http.StatusOK, res)
}

func (h *Handler) DeleteClientHandler(c echo.Context) error {
	ctx := c.Request().Context()

	clientId := c.Param(paramKeyClientId)
	if clientId == "" {
		return c.JSON(http.StatusBadRequest, "clientId is required")
	}

	userID, ok := ctx.Value(domain.ContextKeyUser).(domain.TrapID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, "unauthorized")
	}

	id, err := uuid.Parse(clientId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err)
	}

	err = h.usecase.DeleteClient(ctx, userID, domain.ClientID(id))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	return c.NoContent(http.StatusNoContent)
}
