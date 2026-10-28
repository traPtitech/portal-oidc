package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrAccessTokenNotFound = errors.New("access token not found")

type AccessTokenRepository interface {
	Create(ctx context.Context, t domain.AccessToken) error
	GetBySignature(ctx context.Context, signature string) (domain.AccessToken, error)
	DeleteBySignature(ctx context.Context, signature string) error
	DeleteByRequestID(ctx context.Context, requestID string) error
	RevokeByRequestID(ctx context.Context, requestID string) error
}

type accessTokenRepository struct {
	queries *oidc.Queries
}

func NewAccessTokenRepository(queries *oidc.Queries) AccessTokenRepository {
	return &accessTokenRepository{queries: queries}
}

func (r *accessTokenRepository) Create(ctx context.Context, t domain.AccessToken) error {
	id := t.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	return r.queries.CreateAccessToken(ctx, oidc.CreateAccessTokenParams{
		ID:        id,
		Signature: t.Signature,
		RequestID: t.RequestID,
		ClientID:  t.ClientID,
		UserID:    nullUUID(t.UserID),
		Scopes:    strings.Join(t.Scopes, " "),
		ExpiresAt: t.ExpiresAt,
	})
}

func (r *accessTokenRepository) GetBySignature(ctx context.Context, signature string) (domain.AccessToken, error) {
	row, err := r.queries.GetAccessTokenBySignature(ctx, signature)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AccessToken{}, ErrAccessTokenNotFound
		}
		return domain.AccessToken{}, err
	}
	return toDomainAccessToken(row), nil
}

func (r *accessTokenRepository) DeleteBySignature(ctx context.Context, signature string) error {
	return r.queries.DeleteAccessTokenBySignature(ctx, signature)
}

func (r *accessTokenRepository) DeleteByRequestID(ctx context.Context, requestID string) error {
	return r.queries.DeleteAccessTokensByRequestID(ctx, requestID)
}

func (r *accessTokenRepository) RevokeByRequestID(ctx context.Context, requestID string) error {
	return r.queries.RevokeAccessTokensByRequestID(ctx, requestID)
}

func toDomainAccessToken(row oidc.AccessToken) domain.AccessToken {
	var userID *uuid.UUID
	if row.UserID.Valid {
		id := row.UserID.UUID
		userID = &id
	}
	t := domain.AccessToken{
		ID:        row.ID,
		Signature: row.Signature,
		RequestID: row.RequestID,
		ClientID:  row.ClientID,
		UserID:    userID,
		Scopes:    splitScopes(row.Scopes),
		IssuedAt:  row.IssuedAt,
		ExpiresAt: row.ExpiresAt,
	}
	if row.RevokedAt.Valid {
		t.RevokedAt = &row.RevokedAt.Time
	}
	return t
}
