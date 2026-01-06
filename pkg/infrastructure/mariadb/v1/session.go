package v1

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	mariadb "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1/gen"
)

func convertToDomainSession(sess *mariadb.Session) (domain.Session, error) {
	sessionID, err := uuid.Parse(sess.ID)
	if err != nil {
		return domain.Session{}, errors.Wrap(err, "failed to parse session id")
	}

	var revokedAt *time.Time
	if sess.RevokedAt.Valid {
		revokedAt = &sess.RevokedAt.Time
	}

	return domain.Session{
		ID:           domain.SessionID(sessionID),
		UserID:       domain.TrapID(sess.UserID),
		UserAgent:    sess.UserAgent.String,
		IPAddress:    sess.IpAddress.String,
		AuthTime:     sess.AuthTime,
		LastActiveAt: sess.LastActiveAt,
		ExpiresAt:    sess.ExpiresAt,
		RevokedAt:    revokedAt,
		CreatedAt:    sess.CreatedAt,
	}, nil
}

func convertToDomainUserConsent(consent *mariadb.UserConsent) (domain.UserConsent, error) {
	consentID, err := uuid.Parse(consent.ID)
	if err != nil {
		return domain.UserConsent{}, errors.Wrap(err, "failed to parse consent id")
	}

	clientID, err := uuid.Parse(consent.ClientID)
	if err != nil {
		return domain.UserConsent{}, errors.Wrap(err, "failed to parse client id")
	}

	var scopes []string
	if err := json.Unmarshal(consent.Scopes, &scopes); err != nil {
		return domain.UserConsent{}, errors.Wrap(err, "failed to unmarshal scopes")
	}

	var expiresAt, revokedAt *time.Time
	if consent.ExpiresAt.Valid {
		expiresAt = &consent.ExpiresAt.Time
	}
	if consent.RevokedAt.Valid {
		revokedAt = &consent.RevokedAt.Time
	}

	return domain.UserConsent{
		ID:        domain.UserConsentID(consentID),
		UserID:    domain.TrapID(consent.UserID),
		ClientID:  domain.ClientID(clientID),
		Scopes:    scopes,
		GrantedAt: consent.GrantedAt,
		ExpiresAt: expiresAt,
		RevokedAt: revokedAt,
	}, nil
}

func convertToDomainLoginSession(sess *mariadb.LoginSession) (domain.LoginSession, error) {
	sessionID, err := uuid.Parse(sess.ID)
	if err != nil {
		return domain.LoginSession{}, errors.Wrap(err, "failed to parse login session id")
	}

	clientID, err := uuid.Parse(sess.ClientID)
	if err != nil {
		return domain.LoginSession{}, errors.Wrap(err, "failed to parse client id")
	}

	var scopes []string
	if err := json.Unmarshal(sess.Scopes, &scopes); err != nil {
		return domain.LoginSession{}, errors.Wrap(err, "failed to unmarshal scopes")
	}

	return domain.LoginSession{
		ID:          domain.LoginSessionID(sessionID),
		ClientID:    domain.ClientID(clientID),
		RedirectURI: sess.RedirectUri,
		FormData:    sess.FormData,
		Scopes:      scopes,
		CreatedAt:   sess.CreatedAt,
		ExpiresAt:   sess.ExpiresAt,
	}, nil
}

// Session methods

func (r *MariaDBRepository) CreateSession(ctx context.Context, sess domain.Session) error {
	err := r.q.CreateSession(ctx, mariadb.CreateSessionParams{
		ID:           uuid.UUID(sess.ID).String(),
		UserID:       sess.UserID.String(),
		UserAgent:    sql.NullString{String: sess.UserAgent, Valid: sess.UserAgent != ""},
		IpAddress:    sql.NullString{String: sess.IPAddress, Valid: sess.IPAddress != ""},
		AuthTime:     sess.AuthTime,
		LastActiveAt: sess.LastActiveAt,
		ExpiresAt:    sess.ExpiresAt,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create session")
	}
	return nil
}

func (r *MariaDBRepository) GetSession(ctx context.Context, id domain.SessionID) (domain.Session, error) {
	sess, err := r.q.GetSession(ctx, uuid.UUID(id).String())
	if err != nil {
		return domain.Session{}, errors.Wrap(err, "failed to get session")
	}
	return convertToDomainSession(&sess)
}

func (r *MariaDBRepository) UpdateSessionLastActive(ctx context.Context, id domain.SessionID, lastActiveAt time.Time) error {
	err := r.q.UpdateSessionLastActive(ctx, mariadb.UpdateSessionLastActiveParams{
		ID:           uuid.UUID(id).String(),
		LastActiveAt: lastActiveAt,
	})
	if err != nil {
		return errors.Wrap(err, "failed to update session last active")
	}
	return nil
}

func (r *MariaDBRepository) RevokeSession(ctx context.Context, id domain.SessionID) error {
	err := r.q.RevokeSession(ctx, uuid.UUID(id).String())
	if err != nil {
		return errors.Wrap(err, "failed to revoke session")
	}
	return nil
}

func (r *MariaDBRepository) ListSessionsByUser(ctx context.Context, userID domain.TrapID) ([]domain.Session, error) {
	sessions, err := r.q.ListSessionsByUser(ctx, userID.String())
	if err != nil {
		return nil, errors.Wrap(err, "failed to list sessions")
	}

	result := make([]domain.Session, len(sessions))
	for i, sess := range sessions {
		s, err := convertToDomainSession(&sess)
		if err != nil {
			return nil, errors.Wrap(err, "failed to convert session")
		}
		result[i] = s
	}
	return result, nil
}

// UserConsent methods

func (r *MariaDBRepository) CreateUserConsent(ctx context.Context, consent domain.UserConsent) error {
	scopes, err := json.Marshal(consent.Scopes)
	if err != nil {
		return errors.Wrap(err, "failed to marshal scopes")
	}

	err = r.q.CreateUserConsent(ctx, mariadb.CreateUserConsentParams{
		ID:        uuid.UUID(consent.ID).String(),
		UserID:    consent.UserID.String(),
		ClientID:  uuid.UUID(consent.ClientID).String(),
		Scopes:    scopes,
		GrantedAt: consent.GrantedAt,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create user consent")
	}
	return nil
}

func (r *MariaDBRepository) GetUserConsent(ctx context.Context, userID domain.TrapID, clientID domain.ClientID) (domain.UserConsent, error) {
	consent, err := r.q.GetUserConsent(ctx, mariadb.GetUserConsentParams{
		UserID:   userID.String(),
		ClientID: uuid.UUID(clientID).String(),
	})
	if err != nil {
		return domain.UserConsent{}, errors.Wrap(err, "failed to get user consent")
	}
	return convertToDomainUserConsent(&consent)
}

func (r *MariaDBRepository) UpdateUserConsentScopes(ctx context.Context, userID domain.TrapID, clientID domain.ClientID, scopes []string, grantedAt time.Time) error {
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return errors.Wrap(err, "failed to marshal scopes")
	}

	err = r.q.UpdateUserConsentScopes(ctx, mariadb.UpdateUserConsentScopesParams{
		UserID:    userID.String(),
		ClientID:  uuid.UUID(clientID).String(),
		Scopes:    scopesJSON,
		GrantedAt: grantedAt,
	})
	if err != nil {
		return errors.Wrap(err, "failed to update user consent scopes")
	}
	return nil
}

func (r *MariaDBRepository) RevokeUserConsent(ctx context.Context, userID domain.TrapID, clientID domain.ClientID) error {
	err := r.q.RevokeUserConsent(ctx, mariadb.RevokeUserConsentParams{
		UserID:   userID.String(),
		ClientID: uuid.UUID(clientID).String(),
	})
	if err != nil {
		return errors.Wrap(err, "failed to revoke user consent")
	}
	return nil
}

// LoginSession methods

func (r *MariaDBRepository) CreateLoginSession(ctx context.Context, sess domain.LoginSession) error {
	scopes, err := json.Marshal(sess.Scopes)
	if err != nil {
		return errors.Wrap(err, "failed to marshal scopes")
	}

	err = r.q.CreateLoginSession(ctx, mariadb.CreateLoginSessionParams{
		ID:          uuid.UUID(sess.ID).String(),
		ClientID:    uuid.UUID(sess.ClientID).String(),
		RedirectUri: sess.RedirectURI,
		FormData:    sess.FormData,
		Scopes:      scopes,
		ExpiresAt:   sess.ExpiresAt,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create login session")
	}
	return nil
}

func (r *MariaDBRepository) GetLoginSession(ctx context.Context, id domain.LoginSessionID) (domain.LoginSession, error) {
	sess, err := r.q.GetLoginSession(ctx, uuid.UUID(id).String())
	if err != nil {
		return domain.LoginSession{}, errors.Wrap(err, "failed to get login session")
	}
	return convertToDomainLoginSession(&sess)
}

func (r *MariaDBRepository) DeleteLoginSession(ctx context.Context, id domain.LoginSessionID) error {
	err := r.q.DeleteLoginSession(ctx, uuid.UUID(id).String())
	if err != nil {
		return errors.Wrap(err, "failed to delete login session")
	}
	return nil
}
