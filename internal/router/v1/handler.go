package v1

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/traPtitech/portal-oidc/internal/repository/oidc"
	"github.com/traPtitech/portal-oidc/internal/router/v1/gen"
)

type Handler struct {
	queries *oidc.Queries
}

func NewHandler(queries *oidc.Queries) *Handler {
	return &Handler{queries: queries}
}

func (h *Handler) GetClients(ctx context.Context, _ gen.GetClientsRequestObject) (gen.GetClientsResponseObject, error) {
	clients, err := h.queries.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]gen.Client, len(clients))
	for i, c := range clients {
		client, err := toGenClient(c)
		if err != nil {
			return nil, err
		}
		result[i] = client
	}

	return gen.GetClients200JSONResponse(result), nil
}

func (h *Handler) CreateClient(ctx context.Context, req gen.CreateClientRequestObject) (gen.CreateClientResponseObject, error) {
	clientID := uuid.New()
	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	redirectURIs, err := json.Marshal(req.Body.RedirectUris)
	if err != nil {
		return nil, err
	}

	err = h.queries.CreateClient(ctx, oidc.CreateClientParams{
		ClientID:         clientID.String(),
		ClientSecretHash: sql.NullString{String: string(hash), Valid: true},
		Name:             req.Body.Name,
		ClientType:       string(req.Body.ClientType),
		RedirectUris:     redirectURIs,
	})
	if err != nil {
		return nil, err
	}

	created, err := h.queries.GetClient(ctx, clientID.String())
	if err != nil {
		return nil, err
	}

	client, err := toGenClient(created)
	if err != nil {
		return nil, err
	}

	return gen.CreateClient201JSONResponse{
		ClientId:     client.ClientId,
		ClientSecret: secret,
		ClientType:   client.ClientType,
		CreatedAt:    client.CreatedAt,
		Name:         client.Name,
		RedirectUris: client.RedirectUris,
		UpdatedAt:    client.UpdatedAt,
	}, nil
}

func (h *Handler) GetClient(ctx context.Context, req gen.GetClientRequestObject) (gen.GetClientResponseObject, error) {
	client, err := h.queries.GetClient(ctx, req.ClientId.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return gen.GetClient404Response{}, nil
		}
		return nil, err
	}

	result, err := toGenClient(client)
	if err != nil {
		return nil, err
	}

	return gen.GetClient200JSONResponse(result), nil
}

func (h *Handler) UpdateClient(ctx context.Context, req gen.UpdateClientRequestObject) (gen.UpdateClientResponseObject, error) {
	_, err := h.queries.GetClient(ctx, req.ClientId.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return gen.UpdateClient404Response{}, nil
		}
		return nil, err
	}

	redirectURIs, err := json.Marshal(req.Body.RedirectUris)
	if err != nil {
		return nil, err
	}

	err = h.queries.UpdateClient(ctx, oidc.UpdateClientParams{
		ClientID:     req.ClientId.String(),
		Name:         req.Body.Name,
		ClientType:   string(req.Body.ClientType),
		RedirectUris: redirectURIs,
	})
	if err != nil {
		return nil, err
	}

	updated, err := h.queries.GetClient(ctx, req.ClientId.String())
	if err != nil {
		return nil, err
	}

	result, err := toGenClient(updated)
	if err != nil {
		return nil, err
	}

	return gen.UpdateClient200JSONResponse(result), nil
}

func (h *Handler) DeleteClient(ctx context.Context, req gen.DeleteClientRequestObject) (gen.DeleteClientResponseObject, error) {
	_, err := h.queries.GetClient(ctx, req.ClientId.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return gen.DeleteClient404Response{}, nil
		}
		return nil, err
	}

	err = h.queries.DeleteClient(ctx, req.ClientId.String())
	if err != nil {
		return nil, err
	}

	return gen.DeleteClient204Response{}, nil
}

func (h *Handler) RegenerateClientSecret(ctx context.Context, req gen.RegenerateClientSecretRequestObject) (gen.RegenerateClientSecretResponseObject, error) {
	_, err := h.queries.GetClient(ctx, req.ClientId.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return gen.RegenerateClientSecret404Response{}, nil
		}
		return nil, err
	}

	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	err = h.queries.UpdateClientSecret(ctx, oidc.UpdateClientSecretParams{
		ClientID:         req.ClientId.String(),
		ClientSecretHash: sql.NullString{String: string(hash), Valid: true},
	})
	if err != nil {
		return nil, err
	}

	return gen.RegenerateClientSecret200JSONResponse{
		ClientSecret: secret,
	}, nil
}

func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func toGenClient(c oidc.Client) (gen.Client, error) {
	clientID, err := uuid.Parse(c.ClientID)
	if err != nil {
		return gen.Client{}, err
	}

	var redirectURIs []string
	if err := json.Unmarshal(c.RedirectUris, &redirectURIs); err != nil {
		return gen.Client{}, err
	}

	return gen.Client{
		ClientId:     clientID,
		Name:         c.Name,
		ClientType:   gen.ClientType(c.ClientType),
		RedirectUris: redirectURIs,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}, nil
}
