package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrOIDCSessionNotFound = errors.New("OIDC session not found")

type OIDCSessionRepository interface {
	Create(ctx context.Context, session domain.OIDCSession) error
	Get(ctx context.Context, authorizeCode string) (domain.OIDCSession, error)
	Delete(ctx context.Context, authorizeCode string) error
}

type oidcSessionRepository struct {
	queries *oidc.Queries
}

func NewOIDCSessionRepository(queries *oidc.Queries) OIDCSessionRepository {
	return &oidcSessionRepository{queries: queries}
}

func (r *oidcSessionRepository) Create(ctx context.Context, session domain.OIDCSession) error {
	return r.queries.CreateOIDCSession(ctx, oidc.CreateOIDCSessionParams{
		AuthorizeCode: session.AuthorizeCode,
		ClientID:      session.ClientID,
		UserID:        session.UserID,
		Scopes:        strings.Join(session.Scopes, " "),
		Nonce: sql.NullString{
			String: session.Nonce,
			Valid:  session.Nonce != "",
		},
		AuthTime:    session.AuthTime,
		RequestedAt: session.RequestedAt,
	})
}

func (r *oidcSessionRepository) Get(ctx context.Context, authorizeCode string) (domain.OIDCSession, error) {
	dbSession, err := r.queries.GetOIDCSession(ctx, authorizeCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.OIDCSession{}, ErrOIDCSessionNotFound
		}
		return domain.OIDCSession{}, err
	}

	return toDomainOIDCSession(dbSession), nil
}

func (r *oidcSessionRepository) Delete(ctx context.Context, authorizeCode string) error {
	return r.queries.DeleteOIDCSession(ctx, authorizeCode)
}

func toDomainOIDCSession(db oidc.OidcSession) domain.OIDCSession {
	return domain.OIDCSession{
		AuthorizeCode: db.AuthorizeCode,
		ClientID:      db.ClientID,
		UserID:        db.UserID,
		Nonce:         db.Nonce.String,
		AuthTime:      db.AuthTime,
		Scopes:        splitScopes(db.Scopes),
		RequestedAt:   db.RequestedAt,
		CreatedAt:     db.CreatedAt,
	}
}
