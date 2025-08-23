package store

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/traPtitech/portal-oidc/pkg/domain"
	"github.com/traPtitech/portal-oidc/pkg/domain/repository"
)

type Store struct {
	repo repository.Repository
}

func NewStore(repo repository.Repository) *Store {
	return &Store{repo: repo}
}

func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	// client := new(fosite.DefaultClient)
	uuid, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse UUID")
	}

	client, err := s.repo.GetOIDCClient(ctx, domain.ClientID(uuid))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get client")
	}
	fositeClient := &fosite.DefaultClient{
		ID:            uuid.String(),
		Secret:        []byte(client.Secret),
		RedirectURIs:  client.RedirectURIs,
		GrantTypes:    []string{},
		ResponseTypes: []string{},
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

	if blacklistedJTI, exists := s.repo.GetBlacklistJTI(ctx, jti); blacklistedJTI.JTI == jti && exists == nil {
		return fosite.ErrJTIKnown
	}

	if err := s.repo.CreateBlacklistJTI(ctx, jti, after); err != nil {
		return errors.Wrap(err, "Failed to create blacklisted JTI")
	}

	return nil
}
