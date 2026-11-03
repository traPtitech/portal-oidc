package usecase

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/traPtitech/portal-oidc/internal/domain"
	"github.com/traPtitech/portal-oidc/internal/repository"
)

var (
	ErrInvalidPassword = errors.New("invalid credentials")
	ErrUserNotActive   = errors.New("user is not active")
	ErrUserNotFound    = errors.New("user not found")
)

type UserUseCase interface {
	Authenticate(context.Context, string, string) (*domain.User, error)
	GetByID(context.Context, uuid.UUID) (*domain.User, error)
}
type userUseCase struct {
	profiles repository.UserRepository
	accounts repository.AccountRepository
}

func NewUserUseCase(p repository.UserRepository, a repository.AccountRepository) UserUseCase {
	return &userUseCase{p, a}
}
func (u *userUseCase) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	a, err := u.accounts.GetByID(ctx, id)
	if errors.Is(err, repository.ErrAccountNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return u.activeProfile(ctx, a)
}
func (u *userUseCase) activeProfile(ctx context.Context, a *domain.Account) (*domain.User, error) {
	if !a.ExpiresAt.After(time.Now()) {
		return nil, ErrUserNotActive
	}
	user, err := u.profiles.GetByID(ctx, a.UserID)
	if errors.Is(err, repository.ErrUserNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	user.Email = a.Email
	user.EmailVerified = a.EmailVerified
	return user, nil
}
func (u *userUseCase) Authenticate(ctx context.Context, email, secret string) (*domain.User, error) {
	raw, err := domain.DecodeSecret(secret)
	if err != nil {
		return nil, ErrInvalidPassword
	}
	hash := sha256.Sum256(raw)
	a, err := u.accounts.GetByEmail(ctx, domain.NormalizeEmail(email))
	if errors.Is(err, repository.ErrAccountNotFound) {
		return nil, ErrInvalidPassword
	}
	if err != nil {
		return nil, err
	}
	if a.AuthVerifier.Validate() != nil {
		return nil, ErrInvalidPassword
	}
	expected, err := domain.DecodeSecret(a.AuthVerifier.Hash)
	if err != nil {
		return nil, ErrInvalidPassword
	}
	if subtle.ConstantTimeCompare(hash[:], expected) != 1 {
		return nil, ErrInvalidPassword
	}
	return u.activeProfile(ctx, a)
}
