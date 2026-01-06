package usecase

import (
	"context"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

func (u *UseCase) VerifyPassword(ctx context.Context, id domain.TrapID, password string) (bool, error) {
	return u.po.VerifyPassword(ctx, id, password)
}
