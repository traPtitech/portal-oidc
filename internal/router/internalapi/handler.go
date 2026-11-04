package internalapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
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
			c.Response().Header().Set("Cache-Control", "no-store")
			return next(c)
		}
	})
	gen.RegisterHandlers(group, &Handler{accounts})
}
func (h *Handler) ProvisionUser(c *echo.Context) error {
	var body gen.ProvisionRequest
	media, _, err := mime.ParseMediaType(c.Request().Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return c.NoContent(400)
	}
	decoder := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return c.NoContent(400)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return c.NoContent(400)
	}
	a, err := accountFromRequest(body)
	if err != nil {
		return c.NoContent(400)
	}
	created, err := h.accounts.Provision(c.Request().Context(), a)
	switch {
	case errors.Is(err, domain.ErrInvalidAccount):
		return c.NoContent(422)
	case errors.Is(err, repository.ErrAccountConflict):
		return c.NoContent(409)
	case err != nil:
		slog.WarnContext(c.Request().Context(), "identity operation failed", "user_id", a.UserID, "reason", "provision_failed")
		return c.NoContent(500)
	case created:
		return c.NoContent(201)
	default:
		return c.NoContent(200)
	}
}
func (h *Handler) DeleteUser(c *echo.Context, userId uuid.UUID) error {
	if userId == uuid.Nil {
		return c.NoContent(400)
	}
	if err := h.accounts.Delete(c.Request().Context(), userId); err != nil {
		slog.WarnContext(c.Request().Context(), "identity operation failed", "user_id", userId, "reason", "delete_failed")
		return c.NoContent(500)
	}
	return c.NoContent(204)
}

func accountFromRequest(body gen.ProvisionRequest) (domain.Account, error) {
	if body.UserId == nil || body.TrapId == nil || body.Email == nil || body.EmailVerified == nil || body.ExpiresAt == nil || body.AuthVerifier == nil {
		return domain.Account{}, domain.ErrInvalidAccount
	}
	verifier, err := verifierFromRequest(body.AuthVerifier)
	if err != nil {
		return domain.Account{}, err
	}
	return domain.Account{
		UserID: *body.UserId, TrapID: *body.TrapId, Email: *body.Email,
		EmailVerified: *body.EmailVerified, ExpiresAt: *body.ExpiresAt, AuthVerifier: verifier,
	}, nil
}

func verifierFromRequest(v *gen.AuthVerifier) (domain.AuthVerifier, error) {
	if v.Version == nil || v.Alg == nil || v.Params == nil || v.Hash == nil {
		return domain.AuthVerifier{}, domain.ErrInvalidAccount
	}
	k := v.Params
	if k.Kdf == nil || k.Version == nil || k.MemoryKiB == nil || k.Iterations == nil || k.Parallelism == nil {
		return domain.AuthVerifier{}, domain.ErrInvalidAccount
	}
	return domain.AuthVerifier{
		Version: *v.Version, Alg: *v.Alg, Hash: *v.Hash,
		Params: domain.KDFParams{Kdf: *k.Kdf, Version: *k.Version, MemoryKiB: *k.MemoryKiB, Iterations: *k.Iterations, Parallelism: *k.Parallelism},
	}, nil
}
