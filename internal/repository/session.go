package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrUserSessionNotFound = errors.New("user session not found")

type UserSessionRepository interface {
	Create(ctx context.Context, session domain.UserSession) error
	GetBySessionID(ctx context.Context, sessionID string) (domain.UserSession, error)
	ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.UserSession, error)
	Touch(ctx context.Context, sessionID string) error
	Revoke(ctx context.Context, id, userID uuid.UUID) error
	RevokeAllExcept(ctx context.Context, userID uuid.UUID, keepSessionID string) error
}

type userSessionRepository struct {
	queries *oidc.Queries
}

func NewUserSessionRepository(queries *oidc.Queries) UserSessionRepository {
	return &userSessionRepository{queries: queries}
}

func (r *userSessionRepository) Create(ctx context.Context, s domain.UserSession) error {
	id := s.ID
	if id == uuid.Nil {
		id = uuid.New()
	}
	amr := pqtype.NullRawMessage{}
	if len(s.AMR) > 0 {
		raw, err := json.Marshal(s.AMR)
		if err != nil {
			return err
		}
		amr = pqtype.NullRawMessage{RawMessage: raw, Valid: true}
	}
	return r.queries.CreateUserSession(ctx, oidc.CreateUserSessionParams{
		ID:        id,
		SessionID: s.SessionID,
		UserID:    s.UserID,
		UserAgent: nullString(s.UserAgent),
		IpAddress: nullString(s.IPAddress),
		Acr:       nullString(s.ACR),
		Amr:       amr,
		AuthTime:  s.AuthTime,
		ExpiresAt: s.ExpiresAt,
	})
}

func (r *userSessionRepository) GetBySessionID(ctx context.Context, sessionID string) (domain.UserSession, error) {
	row, err := r.queries.GetUserSessionBySessionID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.UserSession{}, ErrUserSessionNotFound
		}
		return domain.UserSession{}, err
	}
	return toDomainUserSession(row)
}

func (r *userSessionRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]domain.UserSession, error) {
	rows, err := r.queries.ListUserSessionsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]domain.UserSession, 0, len(rows))
	for _, row := range rows {
		s, err := toDomainUserSession(row)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (r *userSessionRepository) Touch(ctx context.Context, sessionID string) error {
	return r.queries.TouchUserSession(ctx, sessionID)
}

func (r *userSessionRepository) Revoke(ctx context.Context, id, userID uuid.UUID) error {
	return r.queries.RevokeUserSession(ctx, oidc.RevokeUserSessionParams{
		ID:     id,
		UserID: userID,
	})
}

func (r *userSessionRepository) RevokeAllExcept(ctx context.Context, userID uuid.UUID, keepSessionID string) error {
	return r.queries.RevokeAllUserSessionsExcept(ctx, oidc.RevokeAllUserSessionsExceptParams{
		UserID:    userID,
		SessionID: keepSessionID,
	})
}

func toDomainUserSession(row oidc.UserSession) (domain.UserSession, error) {
	var amr []string
	if row.Amr.Valid {
		if err := json.Unmarshal(row.Amr.RawMessage, &amr); err != nil {
			return domain.UserSession{}, err
		}
	}
	s := domain.UserSession{
		ID:           row.ID,
		SessionID:    row.SessionID,
		UserID:       row.UserID,
		UserAgent:    row.UserAgent.String,
		IPAddress:    row.IpAddress.String,
		ACR:          row.Acr.String,
		AMR:          amr,
		AuthTime:     row.AuthTime,
		LastActiveAt: row.LastActiveAt,
		ExpiresAt:    row.ExpiresAt,
		CreatedAt:    row.CreatedAt,
	}
	if row.RevokedAt.Valid {
		t := row.RevokedAt.Time
		s.RevokedAt = &t
	}
	return s, nil
}
