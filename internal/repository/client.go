package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
)

var ErrClientNotFound = errors.New("client not found")

// ErrClientConflict indicates that a client changed after it was read.
var ErrClientConflict = errors.New("client was concurrently updated")

var ErrInvalidClientMetadata = errors.New("invalid client metadata")

// Default per-client metadata applied when callers do not specify values.
// These match the historical hard-coded behaviour from before the spec-aligned
// columns were added (see traPortal v2 §clients).
var (
	defaultGrantTypes    = []string{"authorization_code", "refresh_token"}
	defaultResponseTypes = []string{"code"}
	defaultScopes        = []string{"openid", "profile", "email"}
	defaultStatus        = "active"
)

type ClientRepository interface {
	Create(ctx context.Context, client *domain.Client, secretHash string) error
	Get(ctx context.Context, clientID uuid.UUID) (*domain.Client, error)
	GetWithSecretHash(ctx context.Context, clientID uuid.UUID) (*domain.Client, string, error)
	List(ctx context.Context) ([]*domain.Client, error)
	// Update replaces the complete metadata snapshot read by Get. UpdatedAt is
	// required for conflict detection. Permission slices must be non-nil; use
	// explicit empty slices to remove permissions. No defaults are applied.
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
	affected, err := r.queries.UpdateClient(ctx, params)
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrClientConflict
	}
	return nil
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
		ClientID:      dbClient.ClientID,
		Name:          dbClient.Name,
		ClientType:    domain.ClientType(dbClient.ClientType),
		RedirectURIs:  redirectURIs,
		GrantTypes:    grantTypes,
		ResponseTypes: responseTypes,
		Scopes:        scopes,
		Status:        dbClient.Status,
		CreatedAt:     dbClient.CreatedAt,
		UpdatedAt:     dbClient.UpdatedAt,
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
	normalized := *client
	normalized.GrantTypes = orDefault(client.GrantTypes, defaultGrantTypes)
	normalized.ResponseTypes = orDefault(client.ResponseTypes, defaultResponseTypes)
	normalized.Scopes = orDefault(client.Scopes, defaultScopes)
	normalized.Status = orDefaultStr(client.Status, defaultStatus)
	params, err := marshalClientMetadata(&normalized)
	if err != nil {
		return oidc.CreateClientParams{}, err
	}
	params.ClientSecretHash = nullString(secretHash)
	return params, nil
}

// marshalClientMetadata only encodes values; callers own defaulting and validation.
func marshalClientMetadata(client *domain.Client) (oidc.CreateClientParams, error) {
	redirectURIs, err := marshalStringArray(client.RedirectURIs)
	if err != nil {
		return oidc.CreateClientParams{}, err
	}
	grantTypes, err := marshalStringArray(client.GrantTypes)
	if err != nil {
		return oidc.CreateClientParams{}, err
	}
	responseTypes, err := marshalStringArray(client.ResponseTypes)
	if err != nil {
		return oidc.CreateClientParams{}, err
	}
	scopes, err := marshalStringArray(client.Scopes)
	if err != nil {
		return oidc.CreateClientParams{}, err
	}

	return oidc.CreateClientParams{
		ClientID:      client.ClientID,
		Name:          client.Name,
		ClientType:    string(client.ClientType),
		RedirectUris:  redirectURIs,
		GrantTypes:    grantTypes,
		ResponseTypes: responseTypes,
		Scopes:        scopes,
		Status:        client.Status,
	}, nil
}

func buildUpdateParams(client *domain.Client) (oidc.UpdateClientParams, error) {
	if client.GrantTypes == nil || client.ResponseTypes == nil || client.Scopes == nil {
		return oidc.UpdateClientParams{}, fmt.Errorf("%w: permission slices must be specified (use empty slices to clear)", ErrInvalidClientMetadata)
	}

	if client.Status != "active" && client.Status != "suspended" {
		return oidc.UpdateClientParams{}, fmt.Errorf("%w: status must be active or suspended", ErrInvalidClientMetadata)
	}

	params, err := marshalClientMetadata(client)
	if err != nil {
		return oidc.UpdateClientParams{}, err
	}

	return oidc.UpdateClientParams{
		UpdatedAt:     client.UpdatedAt,
		ClientID:      params.ClientID,
		Name:          params.Name,
		ClientType:    params.ClientType,
		RedirectUris:  params.RedirectUris,
		GrantTypes:    params.GrantTypes,
		ResponseTypes: params.ResponseTypes,
		Scopes:        params.Scopes,
		Status:        params.Status,
	}, nil
}

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
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
