package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
	"github.com/traPtitech/portal-oidc/pkg/domain/store"
)

type Store struct {
	repo repository.Repository
}

func NewStore(repo repository.Repository) *Store {
	return &Store{repo: repo}
}

var _ store.Store = &Store{}

func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	// client := new(fosite.DefaultClient)
	client_id, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse UUID")
	}

	client, err := s.repo.GetOIDCClient(ctx, domain.ClientID(client_id))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get client")
	}
	fositeClient := &fosite.DefaultClient{
		ID:            client_id.String(),
		Secret:        []byte(client.Secret),
		RedirectURIs:  client.RedirectURIs,
		GrantTypes:    []string{"refresh_token", "authorization_code"},
		ResponseTypes: []string{"code", "code id_token"},
	}
	return fositeClient, nil

}

func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {

	blacklistedJTI, err := s.repo.GetBlacklistJTI(ctx, jti)
	if err != nil {
		return errors.Wrap(err, "Failed to get blacklisted JTI")
	}
	if blacklistedJTI.JTI == jti && blacklistedJTI.After.After(time.Now()) {
		return fosite.ErrJTIKnown
	}

	return nil
}

func (s *Store) SetClientAssertionJWT(ctx context.Context, jti string, after time.Time) error {
	if err := s.repo.DeleteOldBlacklistJTI(ctx); err != nil {
		return errors.Wrap(err, "Failed to delete old blacklisted JTI")
	}

	_, err := s.repo.GetBlacklistJTI(ctx, jti)
	if err != nil && err != sql.ErrNoRows {
		return fosite.ErrJTIKnown
	}
	if err == nil {
		return errors.New("JTI already exists")
	}

	if err := s.repo.CreateBlacklistJTI(ctx, jti, after); err != nil {
		return errors.Wrap(err, "Failed to create blacklisted JTI")
	}

	return nil
}

func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {

	req := &fosite.Request{
		ID:                request.GetID(),
		RequestedAt:       request.GetRequestedAt(),
		Client:            request.GetClient(),
		RequestedScope:    request.GetRequestedScopes(),
		GrantedScope:      request.GetGrantedScopes(),
		Form:              request.GetRequestForm(),
		Session:           request.GetSession(),
		RequestedAudience: request.GetRequestedAudience(),
		GrantedAudience:   request.GetGrantedAudience(),
	}
	if err := s.repo.CreateAccessTokenSession(ctx, req); err != nil {
		return errors.Wrap(err, "Failed to create access token session")
	}

	return nil
}

// https://github.com/ory/fosite/issues/256
func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	request, err := s.repo.GetAccessToken(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get access token session")
	}

	return request, nil
}

func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	err := s.repo.RevokeAccessTokenBySignature(ctx, signature)
	if err != nil {
		return errors.Wrap(err, "Failed to delete access token session")
	}
	return nil
}

func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature, accessTokenSignature string, request fosite.Requester) error {
	req := &fosite.Request{
		ID:                request.GetID(),
		RequestedAt:       request.GetRequestedAt(),
		Client:            request.GetClient(),
		RequestedScope:    request.GetRequestedScopes(),
		GrantedScope:      request.GetGrantedScopes(),
		Form:              request.GetRequestForm(),
		Session:           request.GetSession(),
		RequestedAudience: request.GetRequestedAudience(),
		GrantedAudience:   request.GetGrantedAudience(),
	}
	if err := s.repo.CreateRefreshTokenSession(ctx, req); err != nil {
		return errors.Wrap(err, "Failed to create refresh token session")
	}
	return nil
}

func (s *Store) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	request, err := s.repo.GetRefreshToken(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get refresh token session")
	}

	return request, nil
}

func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	err := s.repo.RevokeRefreshTokenBySignature(ctx, signature)
	if err != nil {
		return errors.Wrap(err, "Failed to delete refresh token session")
	}
	return nil
}

func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	err := s.repo.RevokeAccessTokenByID(ctx, requestID)
	if err != nil {
		return errors.Wrap(err, "Failed to revoke access token")
	}
	return nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	err := s.repo.RevokeRefreshTokenByID(ctx, requestID)
	if err != nil {
		return errors.Wrap(err, "Failed to revoke refresh token")
	}
	return nil
}

func (s *Store) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) (err error) {
	// Graceful token rotation can be implemented here but it's beyond the scope of this example. Check
	// the Ory Hydra implementation for reference.
	if err := s.RevokeRefreshToken(ctx, requestID); err != nil {
		return err
	}
	return s.RevokeAccessToken(ctx, requestID)
}

func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	req := &fosite.Request{
		ID:                request.GetID(),
		RequestedAt:       request.GetRequestedAt(),
		Client:            request.GetClient(),
		RequestedScope:    request.GetRequestedScopes(),
		GrantedScope:      request.GetGrantedScopes(),
		Form:              request.GetRequestForm(),
		Session:           request.GetSession(),
		RequestedAudience: request.GetRequestedAudience(),
		GrantedAudience:   request.GetGrantedAudience(),
	}
	if err := s.repo.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		return errors.Wrap(err, "Failed to create authorize code session")
	}

	return nil
}

func (s *Store) GetAuthorizeCodeSession(ctx context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	request, err := s.repo.GetAuthorizeCodeSession(ctx, code)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get authorize code session")
	}

	return request, nil
}

func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	err := s.repo.RevokeAuthorizeCodeSession(ctx, code)
	if err != nil {
		return errors.Wrap(err, "Failed to invalidate authorize code")
	}
	return nil
}

func (s *Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	req := &fosite.Request{
		ID:                requester.GetID(),
		RequestedAt:       requester.GetRequestedAt(),
		Client:            requester.GetClient(),
		RequestedScope:    requester.GetRequestedScopes(),
		GrantedScope:      requester.GetGrantedScopes(),
		Form:              requester.GetRequestForm(),
		Session:           requester.GetSession(),
		RequestedAudience: requester.GetRequestedAudience(),
		GrantedAudience:   requester.GetGrantedAudience(),
	}
	if err := s.repo.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		return errors.Wrap(err, "Failed to create OpenID Connect session")
	}

	return nil
}

func (s *Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, _ fosite.Requester) (fosite.Requester, error) {
	request, err := s.repo.GetOpenIDConnectSession(ctx, authorizeCode)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get OpenID Connect session")
	}

	return request, nil
}

func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	// revoke istead of delete
	err := s.repo.RevokeOpenIDConnectSession(ctx, authorizeCode)
	if err != nil {
		return errors.Wrap(err, "Failed to delete OpenID Connect session")
	}
	return nil
}

func (s *Store) CreatePKCERequestSession(ctx context.Context, code string, request fosite.Requester) error {
	req := &fosite.Request{
		ID:                request.GetID(),
		RequestedAt:       request.GetRequestedAt(),
		Client:            request.GetClient(),
		RequestedScope:    request.GetRequestedScopes(),
		GrantedScope:      request.GetGrantedScopes(),
		Form:              request.GetRequestForm(),
		Session:           request.GetSession(),
		RequestedAudience: request.GetRequestedAudience(),
		GrantedAudience:   request.GetGrantedAudience(),
	}
	if err := s.repo.CreatePKCERequestSession(ctx, code, req); err != nil {
		return errors.Wrap(err, "Failed to create PKCE request session")
	}

	return nil
}

func (s *Store) GetPKCERequestSession(ctx context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	request, err := s.repo.GetPKCERequestSession(ctx, code)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get PKCE request session")
	}

	return request, nil
}

func (s *Store) DeletePKCERequestSession(ctx context.Context, code string) error {
	err := s.repo.RevokePKCERequestSession(ctx, code)
	if err != nil {
		return errors.Wrap(err, "Failed to delete PKCE request session")
	}
	return nil
}

func (s *Store) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	return nil, fosite.ErrNotFound
}

func (s *Store) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	return nil, fosite.ErrNotFound
}

func (s *Store) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	return nil, fosite.ErrNotFound
}

func (s *Store) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	err := s.ClientAssertionJWTValid(ctx, jti)
	if err != nil {
		return true, nil
	}

	return false, nil
}

func (s *Store) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return s.SetClientAssertionJWT(ctx, jti, exp)
}
