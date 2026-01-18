package v1

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/traPtitech/portal-oidc/internal/adapter/handler/v1/gen"
	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

type Handler struct {
	clientUseCase usecase.ClientUseCase
}

func NewHandler(clientUseCase usecase.ClientUseCase) *Handler {
	return &Handler{clientUseCase: clientUseCase}
}

// Client API endpoints

func (h *Handler) GetClients(ctx echo.Context) error {
	clients, err := h.clientUseCase.List(ctx.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	response := make([]gen.Client, 0, len(clients))
	for _, c := range clients {
		response = append(response, toClientResponse(c))
	}

	return ctx.JSON(http.StatusOK, response)
}

func (h *Handler) CreateClient(ctx echo.Context) error {
	var req gen.ClientCreate
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	client, err := h.clientUseCase.Create(
		ctx.Request().Context(),
		req.Name,
		domain.ClientType(req.ClientType),
		req.RedirectUris,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return ctx.JSON(http.StatusCreated, toClientWithSecretResponse(client))
}

func (h *Handler) GetClient(ctx echo.Context, clientId openapi_types.UUID) error {
	client, err := h.clientUseCase.Get(ctx.Request().Context(), clientId)
	if err != nil {
		if errors.Is(err, usecase.ErrClientNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "client not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return ctx.JSON(http.StatusOK, toClientResponse(client))
}

func (h *Handler) UpdateClient(ctx echo.Context, clientId openapi_types.UUID) error {
	var req gen.ClientUpdate
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	client, err := h.clientUseCase.Update(
		ctx.Request().Context(),
		clientId,
		req.Name,
		domain.ClientType(req.ClientType),
		req.RedirectUris,
	)
	if err != nil {
		if errors.Is(err, usecase.ErrClientNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "client not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return ctx.JSON(http.StatusOK, toClientResponse(client))
}

func (h *Handler) DeleteClient(ctx echo.Context, clientId openapi_types.UUID) error {
	err := h.clientUseCase.Delete(ctx.Request().Context(), clientId)
	if err != nil {
		if errors.Is(err, usecase.ErrClientNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "client not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (h *Handler) RegenerateClientSecret(ctx echo.Context, clientId openapi_types.UUID) error {
	secret, err := h.clientUseCase.RegenerateSecret(ctx.Request().Context(), clientId)
	if err != nil {
		if errors.Is(err, usecase.ErrClientNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "client not found")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return ctx.JSON(http.StatusOK, gen.ClientSecret{
		ClientSecret: secret,
	})
}

// OIDC endpoints (stub implementations)

func (h *Handler) GetJWKS(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, gen.JWKS{
		Keys: []gen.JWK{},
	})
}

func (h *Handler) GetOpenIDConfiguration(ctx echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "not implemented")
}

func (h *Handler) Authorize(ctx echo.Context, params gen.AuthorizeParams) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "not implemented")
}

func (h *Handler) Token(ctx echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "not implemented")
}

func (h *Handler) GetUserInfo(ctx echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented, "not implemented")
}

// Helper functions

func toClientResponse(c *domain.Client) gen.Client {
	return gen.Client{
		ClientId:     c.ClientID,
		Name:         c.Name,
		ClientType:   gen.ClientType(c.ClientType),
		RedirectUris: c.RedirectURIs,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}
}

func toClientWithSecretResponse(c *domain.ClientWithSecret) gen.ClientWithSecret {
	return gen.ClientWithSecret{
		ClientId:     c.ClientID,
		Name:         c.Name,
		ClientType:   gen.ClientType(c.ClientType),
		RedirectUris: c.RedirectURIs,
		ClientSecret: c.ClientSecret,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}
}
