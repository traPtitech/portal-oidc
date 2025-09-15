package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/cockroachdb/errors"
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
	if err := s.repo.CreateTokenSession(ctx, req, domain.TokenTypeAccessToken); err != nil {
		return errors.Wrap(err, "Failed to create access token session")
	}

	return nil
}

// https://github.com/ory/fosite/issues/256
func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	request, err := s.repo.GetAccessTokenSession(ctx, signature)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get access token session")
	}

	return request, nil
}

func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	err := s.repo.DeleteAccessTokenSession(ctx, signature)
	if err != nil {
		return errors.Wrap(err, "Failed to delete access token session")
	}
	return nil
}
