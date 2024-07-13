package v1

import (
	"context"
	"database/sql"
	"unicode/utf8"

	"github.com/cockroachdb/errors"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/portal"
	"github.com/traPtitech/portal-oidc/pkg/domain/rs"
	models "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1/db/gen"
)

type Portal struct {
	db *sql.DB
}

var _ rs.ResourceServer = (*Portal)(nil)
var _ portal.Portal = (*Portal)(nil)

func NewPortal(db *sql.DB) *Portal {
	return &Portal{db: db}
}

func (p *Portal) GetGrade(ctx context.Context, id domain.UserID) (string, error) {
	user, err := models.Users(models.UserWhere.ID.EQ(id.String())).One(ctx, p.db)
	if err != nil {
		return "", errors.Wrap(err, "Failed to get user")
	}

	if utf8.RuneCountInString(user.StudentNumber.String) < 8 {
		return "", errors.New("Invalid student number")
	}

	return string([]rune(user.StudentNumber.String)[:3]), nil
}
