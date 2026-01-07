package v1

import (
	"context"
	"unicode/utf8"

	"github.com/cockroachdb/errors"
	"github.com/traPtitech/portal-oidc/pkg/domain"
)

func (p *Portal) GetGrade(ctx context.Context, id domain.TrapID) (string, error) {
	user, err := p.q.GetUserByTrapID(ctx, id.String())
	if err != nil {
		return "", errors.Wrap(err, "Failed to get user")
	}

	if !user.StudentNumber.Valid || utf8.RuneCountInString(user.StudentNumber.String) < 8 {
		return "", errors.New("Invalid student number")
	}

	return string([]rune(user.StudentNumber.String)[:3]), nil
}
