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

var ErrRefreshTokenNotFound = errors.New("refresh token not found")

type RefreshTokenRepository interface {
	Create(ctx context.Context, t domain.RefreshToken) error
	GetByHash(ctx context.Context, tokenHash string) (domain.RefreshToken, error)
	DeleteByHash(ctx context.Context, tokenHash string) error
	MarkRotated(ctx context.Context, tokenHash string) error
	RevokeByRequestID(ctx context.Context, requestID string) error
	DeleteByRequestID(ctx context.Context, requestID string) error
}

type refreshTokenRepository struct {
	queries *oidc.Queries
}

func NewRefreshTokenRepository(queries *oidc.Queries) RefreshTokenRepository {
	return &refreshTokenRepository{queries: queries}
}

func (r *refreshTokenRepository) Create(ctx context.Context, t domain.RefreshToken) error {
	id := t.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	return r.queries.CreateRefreshToken(ctx, oidc.CreateRefreshTokenParams{
		ID:              id,
		TokenHash:       t.TokenHash,
		RequestID:       t.RequestID,
		ClientID:        t.ClientID,
		UserID:          t.UserID,
		Scopes:          strings.Join(t.Scopes, " "),
		ExpiresAt:       t.ExpiresAt,
		PreviousTokenID: nullUUID(t.PreviousTokenID),
	})
}

func (r *refreshTokenRepository) GetByHash(ctx context.Context, tokenHash string) (domain.RefreshToken, error) {
	row, err := r.queries.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.RefreshToken{}, ErrRefreshTokenNotFound
		}
		return domain.RefreshToken{}, err
	}
	return toDomainRefreshToken(row), nil
}

func (r *refreshTokenRepository) DeleteByHash(ctx context.Context, tokenHash string) error {
	return r.queries.DeleteRefreshTokenByHash(ctx, tokenHash)
}

func (r *refreshTokenRepository) MarkRotated(ctx context.Context, tokenHash string) error {
	return r.queries.MarkRefreshTokenRotated(ctx, tokenHash)
}

func (r *refreshTokenRepository) RevokeByRequestID(ctx context.Context, requestID string) error {
	return r.queries.RevokeRefreshTokensByRequestID(ctx, requestID)
}

func (r *refreshTokenRepository) DeleteByRequestID(ctx context.Context, requestID string) error {
	return r.queries.DeleteRefreshTokensByRequestID(ctx, requestID)
}

func toDomainRefreshToken(row oidc.RefreshToken) domain.RefreshToken {
	t := domain.RefreshToken{
		ID:        row.ID,
		TokenHash: row.TokenHash,
		RequestID: row.RequestID,
		ClientID:  row.ClientID,
		UserID:    row.UserID,
		Scopes:    splitScopes(row.Scopes),
		IssuedAt:  row.IssuedAt,
		ExpiresAt: row.ExpiresAt,
	}
	if row.RotatedAt.Valid {
		t.RotatedAt = &row.RotatedAt.Time
	}
	if row.PreviousTokenID.Valid {
		id := row.PreviousTokenID.UUID
		t.PreviousTokenID = &id
	}
	if row.RevokedAt.Valid {
		t.RevokedAt = &row.RevokedAt.Time
	}
	return t
}
