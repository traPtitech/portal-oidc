package postgres

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/domain/repository"
	postgres "github.com/traPtitech/portal-oidc/internal/infrastructure/postgres/gen"
)

func (r *Repository) CreateClient(ctx context.Context, params repository.CreateClientParams) (domain.Client, error) {
	redirectURIs, err := json.Marshal(params.RedirectURIs)
	if err != nil {
		return domain.Client{}, err
	}

	err = r.q.CreateClient(ctx, postgres.CreateClientParams{
		ClientID:         toPgUUID(uuid.UUID(params.ID)),
		ClientSecretHash: toPgText(params.SecretHash),
		Name:             params.Name,
		ClientType:       params.Type.String(),
		RedirectUris:     redirectURIs,
	})
	if err != nil {
		return domain.Client{}, err
	}

	return r.GetClient(ctx, params.ID)
}

func (r *Repository) GetClient(ctx context.Context, id domain.ClientID) (domain.Client, error) {
	c, err := r.q.GetClient(ctx, toPgUUID(uuid.UUID(id)))
	if err != nil {
		return domain.Client{}, err
	}
	return toDomainClient(c)
}

func (r *Repository) ListClients(ctx context.Context) ([]domain.Client, error) {
	clients, err := r.q.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]domain.Client, 0, len(clients))
	for _, c := range clients {
		dc, err := toDomainClient(c)
		if err != nil {
			return nil, err
		}
		result = append(result, dc)
	}
	return result, nil
}

func (r *Repository) UpdateClient(ctx context.Context, id domain.ClientID, params repository.UpdateClientParams) (domain.Client, error) {
	redirectURIs, err := json.Marshal(params.RedirectURIs)
	if err != nil {
		return domain.Client{}, err
	}

	err = r.q.UpdateClient(ctx, postgres.UpdateClientParams{
		ClientID:     toPgUUID(uuid.UUID(id)),
		Name:         params.Name,
		ClientType:   params.Type.String(),
		RedirectUris: redirectURIs,
	})
	if err != nil {
		return domain.Client{}, err
	}

	return r.GetClient(ctx, id)
}

func (r *Repository) UpdateClientSecret(ctx context.Context, id domain.ClientID, secretHash *string) (domain.Client, error) {
	err := r.q.UpdateClientSecret(ctx, postgres.UpdateClientSecretParams{
		ClientID:         toPgUUID(uuid.UUID(id)),
		ClientSecretHash: toPgText(secretHash),
	})
	if err != nil {
		return domain.Client{}, err
	}

	return r.GetClient(ctx, id)
}

func (r *Repository) DeleteClient(ctx context.Context, id domain.ClientID) error {
	return r.q.DeleteClient(ctx, toPgUUID(uuid.UUID(id)))
}

func toDomainClient(c postgres.Client) (domain.Client, error) {
	clientID, err := uuid.FromBytes(c.ClientID.Bytes[:])
	if err != nil {
		return domain.Client{}, err
	}

	clientType, err := domain.ParseClientType(c.ClientType)
	if err != nil {
		return domain.Client{}, err
	}

	var redirectURIs []string
	if err := json.Unmarshal(c.RedirectUris, &redirectURIs); err != nil {
		return domain.Client{}, err
	}

	return domain.Client{
		ID:           domain.ClientID(clientID),
		SecretHash:   fromPgText(c.ClientSecretHash),
		Name:         c.Name,
		Type:         clientType,
		RedirectURIs: redirectURIs,
		CreatedAt:    c.CreatedAt.Time,
		UpdatedAt:    c.UpdatedAt.Time,
	}, nil
}

func toPgUUID(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: u, Valid: true}
}

func toPgText(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *s, Valid: true}
}

func fromPgText(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}
