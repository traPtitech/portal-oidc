package v1

import (
	"context"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	models "github.com/traPtitech/portal-oidc/pkg/infrastructure/portal/v1/db/gen"
)

func (p *Portal) GetProfile(ctx context.Context, id domain.UserID) (domain.Profile, error) {
	user, err := models.Users(models.UserWhere.ID.EQ(id.String())).One(ctx, p.db)
	if err != nil {
		return domain.Profile{}, errors.Wrap(err, "Failed to get user")
	}

	name := strings.Split(user.AlphabeticName.String, " ")
	var fistName, lastName string
	if len(name) == 2 {
		fistName = name[0]
		lastName = name[1]
	}

	return domain.Profile{
		Name:       user.AlphabeticName.String,
		GivenName:  fistName,
		FamilyName: lastName,
		Profile:    "https://q.trap.jp/api/v3/public/icon/" + id.String(),
	}, nil
}

func (p *Portal) GetEmail(ctx context.Context, id domain.UserID) (domain.Email, error) {
	user, err := models.Users(models.UserWhere.ID.EQ(id.String())).One(ctx, p.db)
	if err != nil {
		return domain.Email{}, errors.Wrap(err, "Failed to get user")
	}
	_vf := false

	return domain.Email{
		Email:         user.Email.String,
		EmailVerified: &_vf,
	}, nil
}

func (p *Portal) GetAddress(ctx context.Context, id domain.UserID) (domain.Address, error) {
	// 一般ユーザーには非公開
	return domain.Address{}, nil
}

func (p *Portal) GetPhone(ctx context.Context, id domain.UserID) (domain.Phone, error) {
	// 一般ユーザーには非公開
	return domain.Phone{}, nil
}
