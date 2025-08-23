package rs

import (
	"context"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type ResourceServer interface {
	GetProfile(context.Context, domain.TrapID) (domain.Profile, error)
	GetEmail(context.Context, domain.TrapID) (domain.Email, error)
	GetAddress(context.Context, domain.TrapID) (domain.Address, error)
	GetPhone(context.Context, domain.TrapID) (domain.Phone, error)
}
