package usecase

import (
	"context"

	"github.com/traPtitech/portal-oidc/pkg/domain"
)

func (u *UseCase) GetUserInfo(ctx context.Context, id domain.TrapID) (domain.UserInfo, error) {
	// とりあえず抽象化は後回し
	profile, err := u.rs.GetProfile(ctx, id)
	if err != nil {
		return domain.UserInfo{}, err
	}

	email, err := u.rs.GetEmail(ctx, id)
	if err != nil {
		return domain.UserInfo{}, err
	}

	grade, err := u.po.GetGrade(ctx, id)
	if err != nil {
		return domain.UserInfo{}, err
	}

	return domain.UserInfo{
		Profile: profile,
		Email:   email,
		Extra: map[string]any{
			domain.ExtrakeyGrade: grade,
		},
	}, nil
}
