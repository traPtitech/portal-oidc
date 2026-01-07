package portal

import (
	"context"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type Portal interface {
	GetGrade(ctx context.Context, id domain.TrapID) (string, error)
}
