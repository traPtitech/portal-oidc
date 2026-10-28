package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrClientNotFound = errors.New("client not found")

var (
	defaultGrantTypes        = []string{"authorization_code"}
	defaultResponseTypes     = []string{"code"}
	defaultScopes            = []string{"openid", "profile", "email"}
	defaultTokenEndpointAuth = "client_secret_basic"
	defaultIDTokenAlg        = "RS256"
	defaultStatus            = "active"
)

type ClientRepository interface {
	Create(ctx context.Context, client *domain.Client, secretHash string) error
	Get(ctx context.Context, clientID uuid.UUID) (*domain.Client, error)
	GetWithSecretHash(ctx context.Context, clientID uuid.UUID) (*domain.Client, string, error)
	List(ctx context.Context) ([]*domain.Client, error)
	Update(ctx context.Context, client *domain.Client) error
	UpdateSecret(ctx context.Context, clientID uuid.UUID, secretHash string) error
	Delete(ctx context.Context, clientID uuid.UUID) error
}

type clientRepository struct {
	queries *oidc.Queries
}

func NewClientRepository(queries *oidc.Queries) ClientRepository {
	return &clientRepository{queries: queries}
}

func (r *clientRepository) Create(ctx context.Context, client *domain.Client, secretHash string) error {
	params, err := buildCreateParams(client, secretHash)
	if err != nil {
		return err
	}
	return r.queries.CreateClient(ctx, params)
}

func (r *clientRepository) Get(ctx context.Context, clientID uuid.UUID) (*domain.Client, error) {
	dbClient, err := r.queries.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}

	return r.toDomain(dbClient)
}

func (r *clientRepository) GetWithSecretHash(ctx context.Context, clientID uuid.UUID) (*domain.Client, string, error) {
	dbClient, err := r.queries.GetClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", ErrClientNotFound
		}
		return nil, "", err
	}

	client, err := r.toDomain(dbClient)
	if err != nil {
		return nil, "", err
	}

	return client, dbClient.ClientSecretHash.String, nil
}

func (r *clientRepository) List(ctx context.Context) ([]*domain.Client, error) {
	dbClients, err := r.queries.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	clients := make([]*domain.Client, 0, len(dbClients))
	for _, dbClient := range dbClients {
		client, err := r.toDomain(dbClient)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}

	return clients, nil
}

func (r *clientRepository) Update(ctx context.Context, client *domain.Client) error {
	params, err := buildUpdateParams(client)
	if err != nil {
		return err
	}
	return r.queries.UpdateClient(ctx, params)
}

func (r *clientRepository) UpdateSecret(ctx context.Context, clientID uuid.UUID, secretHash string) error {
	return r.queries.UpdateClientSecret(ctx, oidc.UpdateClientSecretParams{
		ClientID: clientID,
		ClientSecretHash: sql.NullString{
			String: secretHash,
			Valid:  secretHash != "",
		},
	})
}

func (r *clientRepository) Delete(ctx context.Context, clientID uuid.UUID) error {
	return r.queries.DeleteClient(ctx, clientID)
}

func (r *clientRepository) toDomain(dbClient oidc.Client) (*domain.Client, error) {
	redirectURIs, err := unmarshalStringArray(dbClient.RedirectUris)
	if err != nil {
		return nil, err
	}
	postLogoutURIs, err := unmarshalStringArray(dbClient.PostLogoutRedirectUris)
	if err != nil {
		return nil, err
	}
	allowedOrigins, err := unmarshalStringArray(dbClient.AllowedOrigins)
	if err != nil {
		return nil, err
	}
	grantTypes, err := unmarshalStringArray(dbClient.GrantTypes)
	if err != nil {
		return nil, err
	}
	responseTypes, err := unmarshalStringArray(dbClient.ResponseTypes)
	if err != nil {
		return nil, err
	}
	scopes, err := unmarshalStringArray(dbClient.Scopes)
	if err != nil {
		return nil, err
	}

	return &domain.Client{
		ClientID:               dbClient.ClientID,
		Name:                   dbClient.Name,
		ClientType:             domain.ClientType(dbClient.ClientType),
		RedirectURIs:           redirectURIs,
		PostLogoutRedirectURIs: postLogoutURIs,
		AllowedOrigins:         allowedOrigins,
		GrantTypes:             grantTypes,
		ResponseTypes:          responseTypes,
		Scopes:                 scopes,
		TokenEndpointAuth:      dbClient.TokenEndpointAuth,
		IDTokenAlg:             dbClient.IDTokenAlg,
		Status:                 dbClient.Status,
		CreatedAt:              dbClient.CreatedAt,
		UpdatedAt:              dbClient.UpdatedAt,
	}, nil
}

func unmarshalStringArray(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func marshalStringArray(values []string) (json.RawMessage, error) {
	if values == nil {
		values = []string{}
	}
	return json.Marshal(values)
}

func buildCreateParams(client *domain.Client, secretHash string) (oidc.CreateClientParams, error) {
	redirectURIs, err := marshalStringArray(client.RedirectURIs)
	if err != nil {
		return oidc.CreateClientParams{}, err
	}

	postLogoutURIs, err := marshalStringArray(client.PostLogoutRedirectURIs)
	if err != nil {
		return oidc.CreateClientParams{}, err
	}
	allowedOrigins, err := marshalStringArray(client.AllowedOrigins)
	if err != nil {
		return oidc.CreateClientParams{}, err
	}
	grantTypes, err := marshalStringArray(orDefault(client.GrantTypes, defaultGrantTypes))
	if err != nil {
		return oidc.CreateClientParams{}, err
	}
	responseTypes, err := marshalStringArray(orDefault(client.ResponseTypes, defaultResponseTypes))
	if err != nil {
		return oidc.CreateClientParams{}, err
	}
	scopes, err := marshalStringArray(orDefault(client.Scopes, defaultScopes))
	if err != nil {
		return oidc.CreateClientParams{}, err
	}

	return oidc.CreateClientParams{
		ClientID: client.ClientID,
		ClientSecretHash: sql.NullString{
			String: secretHash,
			Valid:  secretHash != "",
		},
		Name:                   client.Name,
		ClientType:             string(client.ClientType),
		RedirectUris:           redirectURIs,
		PostLogoutRedirectUris: postLogoutURIs,
		AllowedOrigins:         allowedOrigins,
		GrantTypes:             grantTypes,
		ResponseTypes:          responseTypes,
		Scopes:                 scopes,
		TokenEndpointAuth:      orDefaultStr(client.TokenEndpointAuth, defaultTokenEndpointAuth),
		IDTokenAlg:             orDefaultStr(client.IDTokenAlg, defaultIDTokenAlg),
		Status:                 orDefaultStr(client.Status, defaultStatus),
	}, nil
}

func buildUpdateParams(client *domain.Client) (oidc.UpdateClientParams, error) {
	redirectURIs, err := marshalStringArray(client.RedirectURIs)
	if err != nil {
		return oidc.UpdateClientParams{}, err
	}
	postLogoutURIs, err := marshalStringArray(client.PostLogoutRedirectURIs)
	if err != nil {
		return oidc.UpdateClientParams{}, err
	}
	allowedOrigins, err := marshalStringArray(client.AllowedOrigins)
	if err != nil {
		return oidc.UpdateClientParams{}, err
	}
	grantTypes, err := marshalStringArray(orDefault(client.GrantTypes, defaultGrantTypes))
	if err != nil {
		return oidc.UpdateClientParams{}, err
	}
	responseTypes, err := marshalStringArray(orDefault(client.ResponseTypes, defaultResponseTypes))
	if err != nil {
		return oidc.UpdateClientParams{}, err
	}
	scopes, err := marshalStringArray(orDefault(client.Scopes, defaultScopes))
	if err != nil {
		return oidc.UpdateClientParams{}, err
	}

	return oidc.UpdateClientParams{
		ClientID:               client.ClientID,
		Name:                   client.Name,
		ClientType:             string(client.ClientType),
		RedirectUris:           redirectURIs,
		PostLogoutRedirectUris: postLogoutURIs,
		AllowedOrigins:         allowedOrigins,
		GrantTypes:             grantTypes,
		ResponseTypes:          responseTypes,
		Scopes:                 scopes,
		TokenEndpointAuth:      orDefaultStr(client.TokenEndpointAuth, defaultTokenEndpointAuth),
		IDTokenAlg:             orDefaultStr(client.IDTokenAlg, defaultIDTokenAlg),
		Status:                 orDefaultStr(client.Status, defaultStatus),
	}, nil
}

func orDefault(values, fallback []string) []string {
	if values == nil {
		return fallback
	}
	return values
}

func orDefaultStr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
