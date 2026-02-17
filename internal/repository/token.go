package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrTokenNotFound = errors.New("token not found")

type TokenRepository interface {
	Create(ctx context.Context, token domain.Token) error
	GetByAccessToken(ctx context.Context, accessToken string) (domain.Token, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (domain.Token, error)
	GetByID(ctx context.Context, id string) (domain.Token, error)
	DeleteByAccessToken(ctx context.Context, accessToken string) error
	DeleteByRefreshToken(ctx context.Context, refreshToken string) error
	DeleteByID(ctx context.Context, id string) error
	DeleteByRequestID(ctx context.Context, requestID string) error
}

type tokenRepository struct {
	queries *oidc.Queries
}

func NewTokenRepository(queries *oidc.Queries) TokenRepository {
	return &tokenRepository{queries: queries}
}

func (r *tokenRepository) Create(ctx context.Context, token domain.Token) error {
	return r.queries.CreateToken(ctx, oidc.CreateTokenParams{
		ID:          token.ID,
		RequestID:   token.RequestID,
		ClientID:    token.ClientID,
		UserID:      token.UserID,
		AccessToken: token.AccessToken,
		RefreshToken: sql.NullString{
			String: token.RefreshToken,
			Valid:  token.RefreshToken != "",
		},
		Scopes:    strings.Join(token.Scopes, " "),
		ExpiresAt: token.ExpiresAt,
	})
}

func (r *tokenRepository) GetByAccessToken(ctx context.Context, accessToken string) (domain.Token, error) {
	dbToken, err := r.queries.GetTokenByAccessToken(ctx, accessToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Token{}, ErrTokenNotFound
		}
		return domain.Token{}, err
	}

	return toDomainToken(dbToken), nil
}

func (r *tokenRepository) GetByRefreshToken(ctx context.Context, refreshToken string) (domain.Token, error) {
	dbToken, err := r.queries.GetTokenByRefreshToken(ctx, sql.NullString{
		String: refreshToken,
		Valid:  true,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Token{}, ErrTokenNotFound
		}
		return domain.Token{}, err
	}

	return toDomainToken(dbToken), nil
}

func (r *tokenRepository) GetByID(ctx context.Context, id string) (domain.Token, error) {
	dbToken, err := r.queries.GetTokenByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Token{}, ErrTokenNotFound
		}
		return domain.Token{}, err
	}

	return toDomainToken(dbToken), nil
}

func (r *tokenRepository) DeleteByAccessToken(ctx context.Context, accessToken string) error {
	return r.queries.DeleteTokenByAccessToken(ctx, accessToken)
}

func (r *tokenRepository) DeleteByRefreshToken(ctx context.Context, refreshToken string) error {
	return r.queries.DeleteTokenByRefreshToken(ctx, sql.NullString{
		String: refreshToken,
		Valid:  true,
	})
}

func (r *tokenRepository) DeleteByID(ctx context.Context, id string) error {
	return r.queries.DeleteToken(ctx, id)
}

func (r *tokenRepository) DeleteByRequestID(ctx context.Context, requestID string) error {
	return r.queries.DeleteTokensByRequestID(ctx, requestID)
}

func toDomainToken(db oidc.Token) domain.Token {
	return domain.Token{
		ID:           db.ID,
		RequestID:    db.RequestID,
		ClientID:     db.ClientID,
		UserID:       db.UserID,
		AccessToken:  db.AccessToken,
		RefreshToken: db.RefreshToken.String,
		Scopes:       splitScopes(db.Scopes),
		ExpiresAt:    db.ExpiresAt,
		CreatedAt:    db.CreatedAt,
	}
}
