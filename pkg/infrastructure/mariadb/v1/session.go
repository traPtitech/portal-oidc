package v1

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
	mariadb "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1/gen"
)

func (r *Repository) CreateSession(ctx context.Context, params repository.CreateSessionParams) (domain.Session, error) {
	allowedScopes, err := json.Marshal(params.AllowedScopes)
	if err != nil {
		return domain.Session{}, err
	}

	err = r.q.CreateSession(ctx, mariadb.CreateSessionParams{
		SessionID:     uuid.UUID(params.ID).String(),
		UserID:        params.UserID.String(),
		ClientID:      uuid.UUID(params.ClientID).String(),
		AllowedScopes: allowedScopes,
		ExpiresAt:     params.ExpiresAt,
	})
	if err != nil {
		return domain.Session{}, err
	}

	return r.GetSession(ctx, params.ID)
}

func (r *Repository) GetSession(ctx context.Context, id domain.SessionID) (domain.Session, error) {
	s, err := r.q.GetSession(ctx, uuid.UUID(id).String())
	if err != nil {
		return domain.Session{}, err
	}
	return toDomainSession(s)
}

func (r *Repository) DeleteSession(ctx context.Context, id domain.SessionID) error {
	return r.q.DeleteSession(ctx, uuid.UUID(id).String())
}

func (r *Repository) DeleteExpiredSessions(ctx context.Context) error {
	return r.q.DeleteExpiredSessions(ctx)
}

func (r *Repository) CreateLoginSession(ctx context.Context, params repository.CreateLoginSessionParams) (domain.LoginSession, error) {
	allowedScopes, err := json.Marshal(params.AllowedScopes)
	if err != nil {
		return domain.LoginSession{}, err
	}

	err = r.q.CreateLoginSession(ctx, mariadb.CreateLoginSessionParams{
		LoginSessionID: uuid.UUID(params.ID).String(),
		Forms:          params.Forms,
		AllowedScopes:  allowedScopes,
		UserID:         params.UserID.String(),
		ClientID:       uuid.UUID(params.ClientID).String(),
		ExpiresAt:      params.ExpiresAt,
	})
	if err != nil {
		return domain.LoginSession{}, err
	}

	return r.GetLoginSession(ctx, params.ID)
}

func (r *Repository) GetLoginSession(ctx context.Context, id domain.LoginSessionID) (domain.LoginSession, error) {
	s, err := r.q.GetLoginSession(ctx, uuid.UUID(id).String())
	if err != nil {
		return domain.LoginSession{}, err
	}
	return toDomainLoginSession(s)
}

func (r *Repository) DeleteLoginSession(ctx context.Context, id domain.LoginSessionID) error {
	return r.q.DeleteLoginSession(ctx, uuid.UUID(id).String())
}

func (r *Repository) DeleteExpiredLoginSessions(ctx context.Context) error {
	return r.q.DeleteExpiredLoginSessions(ctx)
}

func toDomainSession(s mariadb.Session) (domain.Session, error) {
	sessionID, err := uuid.Parse(s.SessionID)
	if err != nil {
		return domain.Session{}, err
	}

	clientID, err := uuid.Parse(s.ClientID)
	if err != nil {
		return domain.Session{}, err
	}

	var allowedScopes []string
	if err := json.Unmarshal(s.AllowedScopes, &allowedScopes); err != nil {
		return domain.Session{}, err
	}

	return domain.Session{
		ID:            domain.SessionID(sessionID),
		UserID:        domain.TrapID(s.UserID),
		ClientID:      domain.ClientID(clientID),
		AllowedScopes: allowedScopes,
		CreatedAt:     s.CreatedAt,
		ExpiresAt:     s.ExpiresAt,
	}, nil
}

func toDomainLoginSession(s mariadb.LoginSession) (domain.LoginSession, error) {
	loginSessionID, err := uuid.Parse(s.LoginSessionID)
	if err != nil {
		return domain.LoginSession{}, err
	}

	clientID, err := uuid.Parse(s.ClientID)
	if err != nil {
		return domain.LoginSession{}, err
	}

	var allowedScopes []string
	if err := json.Unmarshal(s.AllowedScopes, &allowedScopes); err != nil {
		return domain.LoginSession{}, err
	}

	return domain.LoginSession{
		ID:            domain.LoginSessionID(loginSessionID),
		Forms:         s.Forms,
		AllowedScopes: allowedScopes,
		UserID:        domain.TrapID(s.UserID),
		ClientID:      domain.ClientID(clientID),
		CreatedAt:     s.CreatedAt,
		ExpiresAt:     s.ExpiresAt,
	}, nil
}
