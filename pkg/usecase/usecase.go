package usecase

import "github.com/traPtitech/portal-oidc/pkg/domain/repository"

type UseCase struct {
	repo repository.Repository
}

func NewUseCase(repo repository.Repository) UseCase {
	return UseCase{repo: repo}
}
