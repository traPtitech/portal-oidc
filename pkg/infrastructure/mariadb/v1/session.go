package v1

import (
	"context"
	"database/sql"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	mariadb "github.com/traPtitech/portal-oidc/pkg/infrastructure/mariadb/v1/gen"
)

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

	sessionID, err := uuid.Parse(sess.ID)
	if err != nil {
		return domain.Session{}, errors.Wrap(err, "failed to parse session id")
	}

	return domain.Session{
		ID:           domain.SessionID(sessionID),
		UserID:       domain.TrapID(sess.UserID),
		UserAgent:    sess.UserAgent.String,
		IPAddress:    sess.IpAddress.String,
		AuthTime:     sess.AuthTime,
		LastActiveAt: sess.LastActiveAt,
		ExpiresAt:    sess.ExpiresAt,
		CreatedAt:    sess.CreatedAt,
	}, nil
}

func (r *MariaDBRepository) DeleteSession(ctx context.Context, id domain.SessionID) error {
	err := r.q.DeleteSession(ctx, uuid.UUID(id).String())
	if err != nil {
		return errors.Wrap(err, "failed to delete session")
	}
	return nil
}

// AuthorizationRequest methods

func (r *MariaDBRepository) CreateAuthorizationRequest(ctx context.Context, req domain.AuthorizationRequest) error {
	err := r.q.CreateAuthorizationRequest(ctx, mariadb.CreateAuthorizationRequestParams{
		ID:                  uuid.UUID(req.ID).String(),
		ClientID:            req.ClientID,
		RedirectUri:         req.RedirectURI,
		Scope:               req.Scope,
		State:               sql.NullString{String: req.State, Valid: req.State != ""},
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           req.ExpiresAt,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create authorization request")
	}
	return nil
}

func (r *MariaDBRepository) GetAuthorizationRequest(ctx context.Context, id domain.AuthorizationRequestID) (domain.AuthorizationRequest, error) {
	req, err := r.q.GetAuthorizationRequest(ctx, uuid.UUID(id).String())
	if err != nil {
		return domain.AuthorizationRequest{}, errors.Wrap(err, "failed to get authorization request")
	}

	reqID, err := uuid.Parse(req.ID)
	if err != nil {
		return domain.AuthorizationRequest{}, errors.Wrap(err, "failed to parse authorization request id")
	}

	result := domain.AuthorizationRequest{
		ID:                  domain.AuthorizationRequestID(reqID),
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectUri,
		Scope:               req.Scope,
		State:               req.State.String,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           req.ExpiresAt,
		CreatedAt:           req.CreatedAt,
	}

	if req.UserID.Valid {
		userID := domain.TrapID(req.UserID.String)
		result.UserID = &userID
	}

	return result, nil
}

func (r *MariaDBRepository) UpdateAuthorizationRequestUserID(ctx context.Context, id domain.AuthorizationRequestID, userID domain.TrapID) error {
	err := r.q.UpdateAuthorizationRequestUserID(ctx, mariadb.UpdateAuthorizationRequestUserIDParams{
		ID:     uuid.UUID(id).String(),
		UserID: sql.NullString{String: userID.String(), Valid: true},
	})
	if err != nil {
		return errors.Wrap(err, "failed to update authorization request user id")
	}
	return nil
}

func (r *MariaDBRepository) DeleteAuthorizationRequest(ctx context.Context, id domain.AuthorizationRequestID) error {
	err := r.q.DeleteAuthorizationRequest(ctx, uuid.UUID(id).String())
	if err != nil {
		return errors.Wrap(err, "failed to delete authorization request")
	}
	return nil
}

// AuthorizationCode methods

func (r *MariaDBRepository) CreateAuthorizationCode(ctx context.Context, code domain.AuthorizationCode) error {
	err := r.q.CreateAuthorizationCode(ctx, mariadb.CreateAuthorizationCodeParams{
		Code:                code.Code,
		ClientID:            code.ClientID,
		UserID:              code.UserID.String(),
		RedirectUri:         code.RedirectURI,
		Scope:               code.Scope,
		CodeChallenge:       code.CodeChallenge,
		CodeChallengeMethod: code.CodeChallengeMethod,
		SessionData:         code.SessionData,
		ExpiresAt:           code.ExpiresAt,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create authorization code")
	}
	return nil
}

func (r *MariaDBRepository) GetAuthorizationCode(ctx context.Context, code string) (domain.AuthorizationCode, error) {
	c, err := r.q.GetAuthorizationCode(ctx, code)
	if err != nil {
		return domain.AuthorizationCode{}, errors.Wrap(err, "failed to get authorization code")
	}

	return domain.AuthorizationCode{
		Code:                c.Code,
		ClientID:            c.ClientID,
		UserID:              domain.TrapID(c.UserID),
		RedirectURI:         c.RedirectUri,
		Scope:               c.Scope,
		CodeChallenge:       c.CodeChallenge,
		CodeChallengeMethod: c.CodeChallengeMethod,
		SessionData:         c.SessionData,
		Used:                c.Used,
		ExpiresAt:           c.ExpiresAt,
		CreatedAt:           c.CreatedAt,
	}, nil
}

func (r *MariaDBRepository) MarkAuthorizationCodeUsed(ctx context.Context, code string) error {
	err := r.q.MarkAuthorizationCodeUsed(ctx, code)
	if err != nil {
		return errors.Wrap(err, "failed to mark authorization code used")
	}
	return nil
}

func (r *MariaDBRepository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	err := r.q.DeleteAuthorizationCode(ctx, code)
	if err != nil {
		return errors.Wrap(err, "failed to delete authorization code")
	}
	return nil
}
