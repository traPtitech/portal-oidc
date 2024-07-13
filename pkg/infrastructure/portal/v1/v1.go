package v1

import (
	"database/sql"

	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	"github.com/traPtitech/portal-oidc/pkg/domain/rs"
)

type Portal struct {
	db *sql.DB
}

var _ rs.ResourceServer = (*Portal)(nil)
var _ portal.Portal = (*Portal)(nil)

func NewPortal(db *sql.DB) *Portal {
	return &Portal{db: db}
}
