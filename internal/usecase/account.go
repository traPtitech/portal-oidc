package usecase

import (
	"context"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

type AccountUseCase struct{ repo repository.AccountRepository }

func NewAccountUseCase(r repository.AccountRepository) *AccountUseCase { return &AccountUseCase{r} }
func (u *AccountUseCase) Provision(ctx context.Context, a domain.Account) (bool, error) {
	a.Email = domain.NormalizeEmail(a.Email)
	if err := a.Validate(); err != nil {
		return false, err
	}
	return u.repo.Provision(ctx, a)
}
func (u *AccountUseCase) Delete(ctx context.Context, id uuid.UUID) error {
	return u.repo.Delete(ctx, id)
}
