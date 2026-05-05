package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrTOTPCredentialNotFound = errors.New("TOTP credential not found")

type TOTPCredentialRepository interface {
	Upsert(ctx context.Context, userID uuid.UUID, secret string, enabled bool) error
	Get(ctx context.Context, userID uuid.UUID) (domain.TOTPCredential, error)
	Enable(ctx context.Context, userID uuid.UUID) error
	Touch(ctx context.Context, userID uuid.UUID) error
	Delete(ctx context.Context, userID uuid.UUID) error
}

type totpCredentialRepository struct {
	queries *oidc.Queries
}

func NewTOTPCredentialRepository(queries *oidc.Queries) TOTPCredentialRepository {
	return &totpCredentialRepository{queries: queries}
}

func (r *totpCredentialRepository) Upsert(ctx context.Context, userID uuid.UUID, secret string, enabled bool) error {
	return r.queries.UpsertTOTPCredential(ctx, oidc.UpsertTOTPCredentialParams{
		UserID:  userID,
		Secret:  secret,
		Enabled: enabled,
	})
}

func (r *totpCredentialRepository) Get(ctx context.Context, userID uuid.UUID) (domain.TOTPCredential, error) {
	row, err := r.queries.GetTOTPCredential(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.TOTPCredential{}, ErrTOTPCredentialNotFound
		}
		return domain.TOTPCredential{}, err
	}
	c := domain.TOTPCredential{
		UserID:    row.UserID,
		Secret:    row.Secret,
		Enabled:   row.Enabled,
		CreatedAt: row.CreatedAt,
	}
	if row.LastUsedAt.Valid {
		c.LastUsedAt = &row.LastUsedAt.Time
	}
	return c, nil
}

func (r *totpCredentialRepository) Enable(ctx context.Context, userID uuid.UUID) error {
	return r.queries.EnableTOTPCredential(ctx, userID)
}

func (r *totpCredentialRepository) Touch(ctx context.Context, userID uuid.UUID) error {
	return r.queries.TouchTOTPCredential(ctx, userID)
}

func (r *totpCredentialRepository) Delete(ctx context.Context, userID uuid.UUID) error {
	return r.queries.DeleteTOTPCredential(ctx, userID)
}
