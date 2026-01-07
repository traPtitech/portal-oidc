package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/domain/random"
	"github.com/traPtitech/portal-oidc/internal/domain/repository"
)

// CreateClientResult contains the created client and the raw secret (only returned on creation)
type CreateClientResult struct {
	Client    domain.Client
	RawSecret string // Only available on creation
}

type CreateClientParams struct {
	Name         string
	Type         domain.ClientType
	RedirectURIs []string
}

func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func (u *UseCase) CreateClient(ctx context.Context, params CreateClientParams) (CreateClientResult, error) {
	id := domain.ClientID(uuid.New())

	var secretHash *string
	var rawSecret string
	if params.Type == domain.ClientTypeConfidential {
		rawSecret = random.GenerateRandomString(32)
		hash := hashSecret(rawSecret)
		secretHash = &hash
	}

	client, err := u.repo.CreateClient(ctx, repository.CreateClientParams{
		ID:           id,
		SecretHash:   secretHash,
		Name:         params.Name,
		Type:         params.Type,
		RedirectURIs: params.RedirectURIs,
	})
	if err != nil {
		return CreateClientResult{}, errors.Wrap(err, "Failed to create client")
	}

	return CreateClientResult{Client: client, RawSecret: rawSecret}, nil
}

func (u *UseCase) ListClients(ctx context.Context) ([]domain.Client, error) {
	clients, err := u.repo.ListClients(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to list clients")
	}

	return clients, nil
}

type UpdateClientParams struct {
	Name         string
	Type         domain.ClientType
	RedirectURIs []string
}

func (u *UseCase) UpdateClient(ctx context.Context, id domain.ClientID, params UpdateClientParams) (domain.Client, error) {
	newclient, err := u.repo.UpdateClient(ctx, id, repository.UpdateClientParams{
		Name:         params.Name,
		Type:         params.Type,
		RedirectURIs: params.RedirectURIs,
	})
	if err != nil {
		return domain.Client{}, errors.Wrap(err, "Failed to update client")
	}

	return newclient, nil
}

// UpdateClientSecretResult contains the updated client and the new raw secret
type UpdateClientSecretResult struct {
	Client    domain.Client
	RawSecret string
}

func (u *UseCase) UpdateClientSecret(ctx context.Context, id domain.ClientID) (UpdateClientSecretResult, error) {
	rawSecret := random.GenerateRandomString(32)
	hash := hashSecret(rawSecret)

	newclient, err := u.repo.UpdateClientSecret(ctx, id, &hash)
	if err != nil {
		return UpdateClientSecretResult{}, errors.Wrap(err, "Failed to update client secret")
	}

	return UpdateClientSecretResult{Client: newclient, RawSecret: rawSecret}, nil
}

func (u *UseCase) DeleteClient(ctx context.Context, id domain.ClientID) error {
	err := u.repo.DeleteClient(ctx, id)
	if err != nil {
		return errors.Wrap(err, "Failed to delete client")
	}

	return nil
}
