package usecase

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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
type userUseCase struct{ accounts repository.AccountRepository }

func NewUserUseCase(a repository.AccountRepository) UserUseCase { return &userUseCase{a} }
func (u *userUseCase) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	a, err := u.accounts.GetByID(ctx, id)
	if errors.Is(err, repository.ErrAccountNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return activeUser(a)
}
func activeUser(a *domain.Account) (*domain.User, error) {
	if !a.ExpiresAt.After(time.Now()) {
		return nil, ErrUserNotActive
	}
	return &domain.User{ID: a.UserID, TrapID: a.TrapID, Email: a.Email, EmailVerified: a.EmailVerified}, nil
}
func (u *userUseCase) Authenticate(ctx context.Context, trapID, secret string) (*domain.User, error) {
	raw, err := domain.DecodeSecret(secret)
	if err != nil {
		return nil, ErrInvalidPassword
	}
	a, err := u.accounts.GetByTrapID(ctx, trapID)
	if errors.Is(err, repository.ErrAccountNotFound) {
		return nil, ErrInvalidPassword
	}
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(hash[:])), []byte(a.AuthVerifier.Hash)) != 1 {
		return nil, ErrInvalidPassword
	}
	return activeUser(a)
}
