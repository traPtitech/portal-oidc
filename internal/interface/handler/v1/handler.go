package v1

import (
	"github.com/traPtitech/portal-oidc/internal/usecase"
)

type Handler struct {
	usecase usecase.UseCase
}

func NewHandler(u usecase.UseCase) *Handler {
	return &Handler{
		usecase: u,
	}
}
