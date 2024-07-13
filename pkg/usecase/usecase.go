package usecase

import (
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
	"github.com/traPtitech/portal-oidc/pkg/domain/rs"
)

type UseCase struct {
	repo repository.Repository
	rs   rs.ResourceServer
	po   portal.Portal
}

func NewUseCase(
	repo repository.Repository,
	rs rs.ResourceServer,
	po portal.Portal,
) UseCase {
	return UseCase{
		repo: repo,
		rs:   rs,
		po:   po,
	}
}
