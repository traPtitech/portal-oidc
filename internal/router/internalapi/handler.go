package internalapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/router/internalapi/gen"
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

type Handler struct{ accounts *usecase.AccountUseCase }

func Register(e *echo.Echo, accounts *usecase.AccountUseCase, token string) {
	if token == "" {
		return
	}
	expected := sha256.Sum256([]byte(token))
	group := e.Group("", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			supplied := sha256.Sum256([]byte(c.Request().Header.Get("X-Portal-Internal-Token")))
			if subtle.ConstantTimeCompare(supplied[:], expected[:]) != 1 {
				return c.NoContent(http.StatusUnauthorized)
			}
			return next(c)
		}
	})
	gen.RegisterHandlers(group, &Handler{accounts})
}

func (h *Handler) ProvisionUser(c *echo.Context) error {
	var body gen.ProvisionRequest
	if err := c.Bind(&body); err != nil {
		return c.NoContent(http.StatusBadRequest)
	}
	a := accountFromRequest(body)
	created, err := h.accounts.Provision(c.Request().Context(), a)
	switch {
	case errors.Is(err, domain.ErrInvalidAccount):
		return c.NoContent(http.StatusUnprocessableEntity)
	case errors.Is(err, repository.ErrAccountConflict):
		return c.NoContent(http.StatusConflict)
	case err != nil:
		slog.WarnContext(c.Request().Context(), "identity operation failed", "user_id", a.UserID, "reason", "provision_failed")
		return c.NoContent(http.StatusInternalServerError)
	case created:
		return c.NoContent(http.StatusCreated)
	default:
		return c.NoContent(http.StatusOK)
	}
}

func (h *Handler) DeleteUser(c *echo.Context, userId uuid.UUID) error {
	if err := h.accounts.Delete(c.Request().Context(), userId); err != nil {
		slog.WarnContext(c.Request().Context(), "identity operation failed", "user_id", userId, "reason", "delete_failed")
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.NoContent(http.StatusNoContent)
}

func accountFromRequest(body gen.ProvisionRequest) domain.Account {
	v, k := body.AuthVerifier, body.AuthVerifier.Params
	return domain.Account{
		UserID: body.UserId, Email: body.Email, EmailVerified: body.EmailVerified, ExpiresAt: body.ExpiresAt,
		AuthVerifier: domain.AuthVerifier{
			Version: v.Version, Alg: v.Alg, Hash: v.Hash,
			Params: domain.KDFParams{Kdf: k.Kdf, Version: k.Version, MemoryKiB: k.MemoryKiB, Iterations: k.Iterations, Parallelism: k.Parallelism},
		},
	}
}
