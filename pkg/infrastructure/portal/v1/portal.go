package v1

import (
	"context"
	"unicode/utf8"

	"github.com/cockroachdb/errors"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	models "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1/db/gen"
)

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
