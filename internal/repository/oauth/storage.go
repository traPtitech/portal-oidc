package oauth

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"
	"github.com/ory/fosite/storage"

	"github.com/traPtitech/portal-oidc/internal/repository"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var (
	_ fosite.Storage                     = (*Storage)(nil)
	_ oauth2.CoreStorage                 = (*Storage)(nil)
	_ oauth2.TokenRevocationStorage      = (*Storage)(nil)
	_ pkce.PKCERequestStorage            = (*Storage)(nil)
	_ openid.OpenIDConnectRequestStorage = (*Storage)(nil)
	_ storage.Transactional              = (*Storage)(nil)
)

type Storage struct {
	db           *sql.DB
	baseQueries  *oidc.Queries
	clients      repository.ClientRepository
	authCodes    repository.AuthCodeRepository
	tokens       repository.TokenRepository
	oidcSessions repository.OIDCSessionRepository
}

func NewStorage(
	db *sql.DB,
	baseQueries *oidc.Queries,
	clients repository.ClientRepository,
	authCodes repository.AuthCodeRepository,
	tokens repository.TokenRepository,
	oidcSessions repository.OIDCSessionRepository,
) *Storage {
	return &Storage{
		db:           db,
		baseQueries:  baseQueries,
		clients:      clients,
		authCodes:    authCodes,
		tokens:       tokens,
		oidcSessions: oidcSessions,
	}
}

type txKey struct{}

type txState struct {
	tx           *sql.Tx
	authCodes    repository.AuthCodeRepository
	tokens       repository.TokenRepository
	oidcSessions repository.OIDCSessionRepository
}

func (s *Storage) BeginTX(ctx context.Context) (context.Context, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ctx, err
	}

	txQueries := s.baseQueries.WithTx(tx)

	return context.WithValue(ctx, txKey{}, &txState{
		tx:           tx,
		authCodes:    repository.NewAuthCodeRepository(txQueries),
		tokens:       repository.NewTokenRepository(txQueries),
		oidcSessions: repository.NewOIDCSessionRepository(txQueries),
	}), nil
}

func (s *Storage) Commit(ctx context.Context) error {
	state, ok := ctx.Value(txKey{}).(*txState)
	if !ok {
		return errors.New("no transaction in context")
	}
	return state.tx.Commit()
}

func (s *Storage) Rollback(ctx context.Context) error {
	state, ok := ctx.Value(txKey{}).(*txState)
	if !ok {
		return errors.New("no transaction in context")
	}
	return state.tx.Rollback()
}

func (s *Storage) getAuthCodes(ctx context.Context) repository.AuthCodeRepository {
	if state, ok := ctx.Value(txKey{}).(*txState); ok {
		return state.authCodes
	}
	return s.authCodes
}

func (s *Storage) getTokens(ctx context.Context) repository.TokenRepository {
	if state, ok := ctx.Value(txKey{}).(*txState); ok {
		return state.tokens
	}
	return s.tokens
}

func (s *Storage) getOIDCSessions(ctx context.Context) repository.OIDCSessionRepository {
	if state, ok := ctx.Value(txKey{}).(*txState); ok {
		return state.oidcSessions
	}
	return s.oidcSessions
}

func (s *Storage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	clientID, err := uuid.Parse(id)
	if err != nil {
		return nil, fosite.ErrNotFound
	}

	client, secretHash, err := s.clients.GetWithSecretHash(ctx, clientID)
	if err != nil {
		if errors.Is(err, repository.ErrClientNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	return &Client{
		ID:            client.ClientID.String(),
		Secret:        []byte(secretHash),
		RedirectURIs:  client.RedirectURIs,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
		Public:        client.ClientType == "public",
	}, nil
}

func (s *Storage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return fosite.ErrNotFound
}

func (s *Storage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return nil
}

func newFositeRequest(id string, requestedAt time.Time, client fosite.Client, session *Session, scopes []string, form url.Values) *fosite.Request {
	req := &fosite.Request{
		ID:          id,
		RequestedAt: requestedAt,
		Client:      client,
		Session:     session,
		Form:        form,
	}
	req.SetRequestedScopes(scopes)
	for _, scope := range scopes {
		req.GrantScope(scope)
	}
	return req
}
