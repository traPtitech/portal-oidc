package portal

import (
	"context"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

type Portal interface {
	GetGrade(ctx context.Context, id domain.UserID) (string, error)
}

type PortalUserID string

var _ domain.UserID = PortalUserID("")

func (p PortalUserID) String() string {
	return string(p)
}

func (p PortalUserID) ID() any {
	return string(p)
}
