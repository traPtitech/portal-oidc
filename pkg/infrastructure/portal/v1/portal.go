package v1

import (
	"context"
	"unicode/utf8"

	"github.com/cockroachdb/errors"
	"golang.org/x/crypto/bcrypt"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

func (p *Portal) GetGrade(ctx context.Context, id domain.TrapID) (string, error) {
	user, err := p.q.GetUserByID(ctx, id.String())
	if err != nil {
		return "", errors.Wrap(err, "Failed to get user")
	}

	if utf8.RuneCountInString(user.StudentNumber.String) < 8 {
		return "", errors.New("Invalid student number")
	}

	return string([]rune(user.StudentNumber.String)[:3]), nil
}

func (p *Portal) VerifyPassword(ctx context.Context, id domain.TrapID, password string) (bool, error) {
	user, err := p.q.GetUserAuth(ctx, id.String())
	if err != nil {
		return false, errors.Wrap(err, "Failed to get user")
	}

	if !user.Password.Valid {
		return false, errors.New("User has no password set")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password.String), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, errors.Wrap(err, "Failed to compare password")
	}

	return true, nil
}
