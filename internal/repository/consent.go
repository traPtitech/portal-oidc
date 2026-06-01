package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrUserConsentNotFound = errors.New("user consent not found")

type UserConsentRepository interface {
	Upsert(ctx context.Context, consent domain.UserConsent) error
	Get(ctx context.Context, userID, clientID uuid.UUID) (domain.UserConsent, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.UserConsent, error)
	Revoke(ctx context.Context, userID, clientID uuid.UUID) error
}

type userConsentRepository struct {
	queries *oidc.Queries
}

func NewUserConsentRepository(queries *oidc.Queries) UserConsentRepository {
	return &userConsentRepository{queries: queries}
}

func (r *userConsentRepository) Upsert(ctx context.Context, consent domain.UserConsent) error {
	scopes, err := json.Marshal(consent.Scopes)
	if err != nil {
		return err
	}
	id := consent.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	return r.queries.UpsertUserConsent(ctx, oidc.UpsertUserConsentParams{
		ID:       id,
		UserID:   consent.UserID,
		ClientID: consent.ClientID,
		Scopes:   scopes,
	})
}

func (r *userConsentRepository) Get(ctx context.Context, userID, clientID uuid.UUID) (domain.UserConsent, error) {
	row, err := r.queries.GetUserConsent(ctx, oidc.GetUserConsentParams{
		UserID:   userID,
		ClientID: clientID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.UserConsent{}, ErrUserConsentNotFound
		}
		return domain.UserConsent{}, err
	}
	return toDomainUserConsent(row)
}

func (r *userConsentRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.UserConsent, error) {
	rows, err := r.queries.ListUserConsentsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.UserConsent, 0, len(rows))
	for _, row := range rows {
		c, err := toDomainUserConsent(row)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (r *userConsentRepository) Revoke(ctx context.Context, userID, clientID uuid.UUID) error {
	return r.queries.RevokeUserConsent(ctx, oidc.RevokeUserConsentParams{
		UserID:   userID,
		ClientID: clientID,
	})
}

func toDomainUserConsent(row oidc.UserConsent) (domain.UserConsent, error) {
	var scopes []string
	if len(row.Scopes) > 0 {
		if err := json.Unmarshal(row.Scopes, &scopes); err != nil {
			return domain.UserConsent{}, err
		}
	}
	consent := domain.UserConsent{
		ID:        row.ID,
		UserID:    row.UserID,
		ClientID:  row.ClientID,
		Scopes:    scopes,
		GrantedAt: row.GrantedAt,
	}
	if row.ExpiresAt.Valid {
		t := row.ExpiresAt.Time
		consent.ExpiresAt = &t
	}
	if row.RevokedAt.Valid {
		t := row.RevokedAt.Time
		consent.RevokedAt = &t
	}
	return consent, nil
}
