package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

var ErrClientNotFound = errors.New("client not found")

type ClientUseCase interface {
	Create(ctx context.Context, name string, clientType domain.ClientType, redirectURIs []string) (*domain.ClientWithSecret, error)
	Get(ctx context.Context, clientID uuid.UUID) (*domain.Client, error)
	List(ctx context.Context) ([]*domain.Client, error)
	Update(ctx context.Context, clientID uuid.UUID, name string, clientType domain.ClientType, redirectURIs []string) (*domain.Client, error)
	RegenerateSecret(ctx context.Context, clientID uuid.UUID) (string, error)
	Delete(ctx context.Context, clientID uuid.UUID) error
}

type clientUseCase struct {
	repo repository.ClientRepository
}

func NewClientUseCase(repo repository.ClientRepository) ClientUseCase {
	return &clientUseCase{repo: repo}
}

func (u *clientUseCase) Create(ctx context.Context, name string, clientType domain.ClientType, redirectURIs []string) (*domain.ClientWithSecret, error) {
	clientID := uuid.New()

	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}

	secretHash, err := hashSecret(secret)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	client := &domain.Client{
		ClientID:     clientID,
		Name:         name,
		ClientType:   clientType,
		RedirectURIs: redirectURIs,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := u.repo.Create(ctx, client, secretHash); err != nil {
		return nil, err
	}

	createdClient, err := u.repo.Get(ctx, clientID)
	if err != nil {
		return nil, err
	}

	return &domain.ClientWithSecret{
		Client:       *createdClient,
		ClientSecret: secret,
	}, nil
}

func (u *clientUseCase) Get(ctx context.Context, clientID uuid.UUID) (*domain.Client, error) {
	client, err := u.repo.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, repository.ErrClientNotFound) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	return client, nil
}

func (u *clientUseCase) List(ctx context.Context) ([]*domain.Client, error) {
	return u.repo.List(ctx)
}

func (u *clientUseCase) Update(ctx context.Context, clientID uuid.UUID, name string, clientType domain.ClientType, redirectURIs []string) (*domain.Client, error) {
	existing, err := u.repo.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, repository.ErrClientNotFound) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}

	existing.Name = name
	existing.ClientType = clientType
	existing.RedirectURIs = redirectURIs

	if err := u.repo.Update(ctx, existing); err != nil {
		return nil, err
	}

	return u.repo.Get(ctx, clientID)
}

func (u *clientUseCase) RegenerateSecret(ctx context.Context, clientID uuid.UUID) (string, error) {
	_, err := u.repo.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, repository.ErrClientNotFound) {
			return "", ErrClientNotFound
		}
		return "", err
	}

	secret, err := generateSecret()
	if err != nil {
		return "", err
	}

	secretHash, err := hashSecret(secret)
	if err != nil {
		return "", err
	}

	if err := u.repo.UpdateSecret(ctx, clientID, secretHash); err != nil {
		return "", err
	}

	return secret, nil
}

func (u *clientUseCase) Delete(ctx context.Context, clientID uuid.UUID) error {
	_, err := u.repo.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, repository.ErrClientNotFound) {
			return ErrClientNotFound
		}
		return err
	}

	return u.repo.Delete(ctx, clientID)
}

func generateSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func hashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
