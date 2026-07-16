package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrSigningKeyNotFound = errors.New("signing key not found")

type SigningKeyRepository interface {
	Create(ctx context.Context, key domain.SigningKey) error
	GetByKID(ctx context.Context, kid string) (domain.SigningKey, error)
	GetActive(ctx context.Context) (domain.SigningKey, error)
	ListPublishable(ctx context.Context) ([]domain.SigningKey, error)
	MarkRotated(ctx context.Context, id uuid.UUID) error
	Revoke(ctx context.Context, id uuid.UUID) error
}

type signingKeyRepository struct {
	queries *oidc.Queries
}

func NewSigningKeyRepository(queries *oidc.Queries) SigningKeyRepository {
	return &signingKeyRepository{queries: queries}
}

func (r *signingKeyRepository) Create(ctx context.Context, key domain.SigningKey) error {
	expiresAt := sql.NullTime{}
	if key.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: *key.ExpiresAt, Valid: true}
	}
	return r.queries.CreateSigningKey(ctx, oidc.CreateSigningKeyParams{
		ID:         key.ID,
		Kid:        key.KID,
		Algorithm:  key.Algorithm,
		Use:        string(key.Use),
		Status:     string(key.Status),
		PublicKey:  key.PublicKeyPEM,
		PrivateKey: key.PrivateKeyPEM,
		ExpiresAt:  expiresAt,
	})
}

func (r *signingKeyRepository) GetByKID(ctx context.Context, kid string) (domain.SigningKey, error) {
	row, err := r.queries.GetSigningKeyByKID(ctx, kid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.SigningKey{}, ErrSigningKeyNotFound
		}
		return domain.SigningKey{}, err
	}
	return toDomainSigningKey(row), nil
}

func (r *signingKeyRepository) GetActive(ctx context.Context) (domain.SigningKey, error) {
	row, err := r.queries.GetActiveSigningKey(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.SigningKey{}, ErrSigningKeyNotFound
		}
		return domain.SigningKey{}, err
	}
	return toDomainSigningKey(row), nil
}

func (r *signingKeyRepository) ListPublishable(ctx context.Context) ([]domain.SigningKey, error) {
	rows, err := r.queries.ListPublishableSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]domain.SigningKey, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, toDomainSigningKey(row))
	}
	return keys, nil
}

func (r *signingKeyRepository) MarkRotated(ctx context.Context, id uuid.UUID) error {
	return r.queries.MarkSigningKeyRotated(ctx, id)
}

func (r *signingKeyRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	return r.queries.RevokeSigningKey(ctx, id)
}

func toDomainSigningKey(row oidc.SigningKey) domain.SigningKey {
	var expiresAt *time.Time
	if row.ExpiresAt.Valid {
		t := row.ExpiresAt.Time
		expiresAt = &t
	}
	var rotatedAt *time.Time
	if row.RotatedAt.Valid {
		t := row.RotatedAt.Time
		rotatedAt = &t
	}
	return domain.SigningKey{
		ID:            row.ID,
		KID:           row.Kid,
		Algorithm:     row.Algorithm,
		Use:           domain.SigningKeyUse(row.Use),
		Status:        domain.SigningKeyStatus(row.Status),
		PublicKeyPEM:  row.PublicKey,
		PrivateKeyPEM: row.PrivateKey,
		ExpiresAt:     expiresAt,
		RotatedAt:     rotatedAt,
		CreatedAt:     row.CreatedAt,
	}
}
