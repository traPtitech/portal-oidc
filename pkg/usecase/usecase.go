package usecase

import (
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
)

type UseCase struct {
	repo repository.Repository
	po   portal.Portal
}

func NewUseCase(
	repo repository.Repository,
	po portal.Portal,
) UseCase {
	return UseCase{
		repo: repo,
		po:   po,
	}
}
