package v1

import (
	"github.com/traPtitech/portal-oidc/pkg/usecase"
)

type Handler struct {
	usecase usecase.UseCase
}

func NewHandler(u usecase.UseCase) *Handler {
	return &Handler{
		usecase: u,
	}
}
