package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrAuthCodeNotFound = errors.New("authorization code not found")

type AuthCodeRepository interface {
	Create(ctx context.Context, authCode domain.AuthCode) error
	Get(ctx context.Context, code string) (domain.AuthCode, error)
	Delete(ctx context.Context, code string) error
	MarkUsed(ctx context.Context, code string) error
	UpdatePKCE(ctx context.Context, code, challenge, method string) error
}

type authCodeRepository struct {
	queries *oidc.Queries
}

func NewAuthCodeRepository(queries *oidc.Queries) AuthCodeRepository {
	return &authCodeRepository{queries: queries}
}

func (r *authCodeRepository) Create(ctx context.Context, authCode domain.AuthCode) error {
	return r.queries.CreateAuthorizationCode(ctx, oidc.CreateAuthorizationCodeParams{
		Code:        authCode.Code,
		ClientID:    authCode.ClientID,
		UserID:      authCode.UserID,
		RedirectUri: authCode.RedirectURI,
		Scopes:      strings.Join(authCode.Scopes, " "),
		CodeChallenge: sql.NullString{
			String: authCode.CodeChallenge,
			Valid:  authCode.CodeChallenge != "",
		},
		CodeChallengeMethod: sql.NullString{
			String: authCode.CodeChallengeMethod,
			Valid:  authCode.CodeChallengeMethod != "",
		},
		Nonce: sql.NullString{
			String: authCode.Nonce,
			Valid:  authCode.Nonce != "",
		},
		ExpiresAt: authCode.ExpiresAt,
	})
}

func (r *authCodeRepository) Get(ctx context.Context, code string) (domain.AuthCode, error) {
	dbCode, err := r.queries.GetAuthorizationCode(ctx, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AuthCode{}, ErrAuthCodeNotFound
		}
		return domain.AuthCode{}, err
	}

	return toDomainAuthCode(dbCode), nil
}

func (r *authCodeRepository) Delete(ctx context.Context, code string) error {
	return r.queries.DeleteAuthorizationCode(ctx, code)
}

func (r *authCodeRepository) MarkUsed(ctx context.Context, code string) error {
	return r.queries.MarkAuthorizationCodeUsed(ctx, code)
}

func (r *authCodeRepository) UpdatePKCE(ctx context.Context, code, challenge, method string) error {
	return r.queries.UpdateAuthorizationCodePKCE(ctx, oidc.UpdateAuthorizationCodePKCEParams{
		CodeChallenge: sql.NullString{
			String: challenge,
			Valid:  challenge != "",
		},
		CodeChallengeMethod: sql.NullString{
			String: method,
			Valid:  method != "",
		},
		Code: code,
	})
}

func toDomainAuthCode(db oidc.AuthorizationCode) domain.AuthCode {
	scopes := splitScopes(db.Scopes)

	return domain.AuthCode{
		Code:                db.Code,
		ClientID:            db.ClientID,
		UserID:              db.UserID,
		RedirectURI:         db.RedirectUri,
		Scopes:              scopes,
		CodeChallenge:       db.CodeChallenge.String,
		CodeChallengeMethod: db.CodeChallengeMethod.String,
		Nonce:               db.Nonce.String,
		Used:                db.Used,
		ExpiresAt:           db.ExpiresAt,
		CreatedAt:           db.CreatedAt,
	}
}

func splitScopes(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, " ")
}
