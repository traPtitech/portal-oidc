package rs

import (
	"context"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type ResourceServer interface {
	GetProfile(context.Context, domain.UserID) (domain.Profile, error)
	GetEmail(context.Context, domain.UserID) (domain.Email, error)
	GetAddress(context.Context, domain.UserID) (domain.Address, error)
	GetPhone(context.Context, domain.UserID) (domain.Phone, error)
	GetResource(context.Context, domain.UserID, domain.ResourceID) (domain.Resource, error)
	GetResources(context.Context, domain.UserID, []domain.ResourceID) ([]domain.Resource, error)
}
