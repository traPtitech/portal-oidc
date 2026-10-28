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

var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	// ErrRefreshTokenNotRotated is returned by RotateBySignature when no
	// active row matched, i.e. a concurrent request already rotated (or
	// removed) the token.
	ErrRefreshTokenNotRotated = errors.New("refresh token not rotated")
)

type RefreshTokenRepository interface {
	Create(ctx context.Context, t domain.RefreshToken) error
	GetBySignature(ctx context.Context, signature string) (domain.RefreshToken, error)
	DeleteBySignature(ctx context.Context, signature string) error
	RotateBySignature(ctx context.Context, signature string) error
	RevokeByRequestID(ctx context.Context, requestID string) error
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
		ID:        id,
		Signature: t.Signature,
		RequestID: t.RequestID,
		ClientID:  t.ClientID,
		UserID:    t.UserID,
		Scopes:    strings.Join(t.Scopes, " "),
		ExpiresAt: t.ExpiresAt,
	})
}

func (r *refreshTokenRepository) GetBySignature(ctx context.Context, signature string) (domain.RefreshToken, error) {
	row, err := r.queries.GetRefreshTokenBySignature(ctx, signature)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.RefreshToken{}, ErrRefreshTokenNotFound
		}
		return domain.RefreshToken{}, err
	}
	return toDomainRefreshToken(row), nil
}

func (r *refreshTokenRepository) DeleteBySignature(ctx context.Context, signature string) error {
	return r.queries.DeleteRefreshTokenBySignature(ctx, signature)
}

func (r *refreshTokenRepository) RotateBySignature(ctx context.Context, signature string) error {
	n, err := r.queries.RotateRefreshTokenBySignature(ctx, signature)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrRefreshTokenNotRotated
	}
	return nil
}

func (r *refreshTokenRepository) RevokeByRequestID(ctx context.Context, requestID string) error {
	return r.queries.RevokeRefreshTokensByRequestID(ctx, requestID)
}

func toDomainRefreshToken(row oidc.RefreshToken) domain.RefreshToken {
	t := domain.RefreshToken{
		ID:        row.ID,
		Signature: row.Signature,
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
	if row.RevokedAt.Valid {
		t.RevokedAt = &row.RevokedAt.Time
	}
	return t
}
