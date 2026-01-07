package portal

import (
	"context"

	"github.com/traPtitech/portal-oidc/internal/domain"
)

type Portal interface {
	GetGrade(ctx context.Context, id domain.TrapID) (string, error)
}
