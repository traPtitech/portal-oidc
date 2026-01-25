package v1

import "github.com/traPtitech/portal-oidc/internal/usecase"

type Handler struct {
	clientUseCase usecase.ClientUseCase
}

func NewHandler(clientUseCase usecase.ClientUseCase) *Handler {
	return &Handler{
		clientUseCase: clientUseCase,
	}
}
