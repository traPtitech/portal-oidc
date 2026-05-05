package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrAccessTokenNotFound = errors.New("access token not found")

type AccessTokenRepository interface {
	Create(ctx context.Context, t domain.AccessToken) error
	GetByJTI(ctx context.Context, jti string) (domain.AccessToken, error)
	DeleteByJTI(ctx context.Context, jti string) error
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
	audience := pqtype.NullRawMessage{}
	if len(t.Audience) > 0 {
		raw, err := json.Marshal(t.Audience)
		if err != nil {
			return err
		}
		audience = pqtype.NullRawMessage{RawMessage: raw, Valid: true}
	}
	return r.queries.CreateAccessToken(ctx, oidc.CreateAccessTokenParams{
		ID:        id,
		Jti:       t.JTI,
		RequestID: t.RequestID,
		ClientID:  t.ClientID,
		UserID:    nullUUID(t.UserID),
		Scopes:    strings.Join(t.Scopes, " "),
		Audience:  audience,
		ExpiresAt: t.ExpiresAt,
	})
}

func (r *accessTokenRepository) GetByJTI(ctx context.Context, jti string) (domain.AccessToken, error) {
	row, err := r.queries.GetAccessTokenByJTI(ctx, jti)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.AccessToken{}, ErrAccessTokenNotFound
		}
		return domain.AccessToken{}, err
	}
	return toDomainAccessToken(row)
}

func (r *accessTokenRepository) DeleteByJTI(ctx context.Context, jti string) error {
	return r.queries.DeleteAccessTokenByJTI(ctx, jti)
}

func (r *accessTokenRepository) DeleteByRequestID(ctx context.Context, requestID string) error {
	return r.queries.DeleteAccessTokensByRequestID(ctx, requestID)
}

func (r *accessTokenRepository) RevokeByRequestID(ctx context.Context, requestID string) error {
	return r.queries.RevokeAccessTokensByRequestID(ctx, requestID)
}

func toDomainAccessToken(row oidc.AccessToken) (domain.AccessToken, error) {
	var audience []string
	if row.Audience.Valid {
		if err := json.Unmarshal(row.Audience.RawMessage, &audience); err != nil {
			return domain.AccessToken{}, err
		}
	}
	var userID *uuid.UUID
	if row.UserID.Valid {
		id := row.UserID.UUID
		userID = &id
	}
	t := domain.AccessToken{
		ID:        row.ID,
		JTI:       row.Jti,
		RequestID: row.RequestID,
		ClientID:  row.ClientID,
		UserID:    userID,
		Scopes:    splitScopes(row.Scopes),
		Audience:  audience,
		IssuedAt:  row.IssuedAt,
		ExpiresAt: row.ExpiresAt,
	}
	if row.RevokedAt.Valid {
		t.RevokedAt = &row.RevokedAt.Time
	}
	return t, nil
}
