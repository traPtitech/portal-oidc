package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/ory/fosite"

	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var _ fosite.Storage = (*Storage)(nil)

type Storage struct {
	queries           *oidc.Queries
	oidcSessions      map[string]fosite.Requester
	oidcSessionsMutex sync.RWMutex
}

func NewStorage(queries *oidc.Queries) *Storage {
	return &Storage{
		queries:      queries,
		oidcSessions: make(map[string]fosite.Requester),
	}
}

func (s *Storage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	dbClient, err := s.queries.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	var redirectURIs []string
	if err := json.Unmarshal(dbClient.RedirectUris, &redirectURIs); err != nil {
		return nil, err
	}

	return &Client{
		ID:            dbClient.ClientID,
		Secret:        []byte(dbClient.ClientSecretHash.String),
		RedirectURIs:  redirectURIs,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
		Public:        dbClient.ClientType == "public",
	}, nil
}

func (s *Storage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return fosite.ErrNotFound
}

func (s *Storage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return nil
}
